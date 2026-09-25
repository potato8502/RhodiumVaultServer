using Microsoft.Data.Sqlite;

namespace RhodiumVaultServer;

/// <summary>
/// SQLite storage. One account, one vault, a rolling history of previous encrypted vaults, and sessions.
/// Every mutating operation is a single IMMEDIATE transaction, so a crash can never leave half-applied state.
/// The database only ever contains ciphertext, public KDF parameters, and one-way hashes.
/// </summary>
public sealed class VaultStore
{
    private readonly string _connectionString;
    private readonly TimeProvider _time;
    private readonly int _maxHistory;

    public VaultStore(string dataDir, TimeProvider time, int maxHistory = 20)
    {
        Directory.CreateDirectory(dataDir);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(dataDir, "vault.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 10,
            Pooling = false,
        }.ToString();
        _time = time;
        _maxHistory = maxHistory;
        Initialize();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_connectionString);
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;";
        cmd.ExecuteNonQuery();
        return c;
    }

    private void Initialize()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL, kdf_memory INTEGER NOT NULL, kdf_iter INTEGER NOT NULL, kdf_par INTEGER NOT NULL,
                auth_hash BLOB NOT NULL, auth_hash_salt BLOB NOT NULL, created_utc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                revision INTEGER NOT NULL, blob TEXT NOT NULL, updated_utc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vault_history (
                revision INTEGER PRIMARY KEY, blob TEXT NOT NULL, salt BLOB NOT NULL,
                kdf_memory INTEGER NOT NULL, kdf_iter INTEGER NOT NULL, kdf_par INTEGER NOT NULL, created_utc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY, created_utc TEXT NOT NULL, last_seen_utc TEXT NOT NULL, expires_utc TEXT NOT NULL);
            """;
        cmd.ExecuteNonQuery();
    }

    private string Now() => _time.GetUtcNow().UtcDateTime.ToString("O");
    private static DateTime Parse(string s) => DateTime.Parse(s, null, System.Globalization.DateTimeStyles.RoundtripKind);

    /// <summary>Starts an IMMEDIATE transaction (takes the write lock up front); finished with explicit COMMIT/ROLLBACK.</summary>
    private static void Begin(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "BEGIN IMMEDIATE";
        cmd.ExecuteNonQuery();
    }

    private static void Exec(SqliteConnection c, string sql, params (string, object?)[] args)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    // ---------- account ----------

    public bool HasAccount()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM account";
        return (long)cmd.ExecuteScalar()! > 0;
    }

    public Account? GetAccount()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT salt, kdf_memory, kdf_iter, kdf_par, auth_hash, auth_hash_salt FROM account WHERE id = 1";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new Account((byte[])r["salt"], new KdfDto(r.GetInt32(1), r.GetInt32(2), r.GetInt32(3)), (byte[])r["auth_hash"], (byte[])r["auth_hash_salt"]);
    }

    /// <summary>Creates the single account and its first vault revision atomically. Returns false if an account already exists.</summary>
    public bool CreateAccount(byte[] salt, KdfDto kdf, byte[] authHash, byte[] authHashSalt, string blobJson)
    {
        using var c = Open();
        Begin(c);
        try
        {
            using (var check = c.CreateCommand())
            {
                check.CommandText = "SELECT COUNT(*) FROM account";
                if ((long)check.ExecuteScalar()! > 0) { Exec(c, "ROLLBACK"); return false; }
            }
            var now = Now();
            Exec(c, "INSERT INTO account (id, salt, kdf_memory, kdf_iter, kdf_par, auth_hash, auth_hash_salt, created_utc) VALUES (1,$s,$m,$i,$p,$h,$hs,$t)",
                ("$s", salt), ("$m", kdf.MemoryKiB), ("$i", kdf.Iterations), ("$p", kdf.Parallelism), ("$h", authHash), ("$hs", authHashSalt), ("$t", now));
            Exec(c, "INSERT INTO vault (id, revision, blob, updated_utc) VALUES (1, 1, $b, $t)", ("$b", blobJson), ("$t", now));
            Exec(c, "COMMIT");
            return true;
        }
        catch { TryRollback(c); throw; }
    }

    // ---------- vault ----------

    public VaultRow? GetVault()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT revision, blob, updated_utc FROM vault WHERE id = 1";
        using var r = cmd.ExecuteReader();
        return r.Read() ? new VaultRow(r.GetInt64(0), r.GetString(1), Parse(r.GetString(2))) : null;
    }

    /// <summary>Optimistic-concurrency save. Returns the new revision, or null if <paramref name="expectedRevision"/> is stale.</summary>
    public long? PutVault(long expectedRevision, string newBlobJson)
    {
        using var c = Open();
        Begin(c);
        try
        {
            var acct = ReadAccountTx(c);
            var (rev, oldBlob) = ReadVaultTx(c);
            if (acct == null || rev != expectedRevision) { Exec(c, "ROLLBACK"); return null; }

            SnapshotTx(c, rev, oldBlob, acct);
            var next = rev + 1;
            Exec(c, "UPDATE vault SET revision=$r, blob=$b, updated_utc=$t WHERE id=1", ("$r", next), ("$b", newBlobJson), ("$t", Now()));
            PruneHistoryTx(c);
            Exec(c, "COMMIT");
            return next;
        }
        catch { TryRollback(c); throw; }
    }

    /// <summary>
    /// Replaces credentials and re-encrypted vault in ONE transaction. Fails (returns null) if the vault revision moved
    /// or the current auth hash changed since the caller verified it. All sessions are invalidated on success.
    /// </summary>
    public long? ChangePassword(long expectedRevision, byte[] expectedOldAuthHash, byte[] newSalt, KdfDto newKdf, byte[] newAuthHash, byte[] newAuthHashSalt, string newBlobJson)
    {
        using var c = Open();
        Begin(c);
        try
        {
            var acct = ReadAccountTx(c);
            var (rev, oldBlob) = ReadVaultTx(c);
            if (acct == null || rev != expectedRevision || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(acct.AuthHash, expectedOldAuthHash))
            { Exec(c, "ROLLBACK"); return null; }

            SnapshotTx(c, rev, oldBlob, acct);
            Exec(c, "UPDATE account SET salt=$s, kdf_memory=$m, kdf_iter=$i, kdf_par=$p, auth_hash=$h, auth_hash_salt=$hs WHERE id=1",
                ("$s", newSalt), ("$m", newKdf.MemoryKiB), ("$i", newKdf.Iterations), ("$p", newKdf.Parallelism), ("$h", newAuthHash), ("$hs", newAuthHashSalt));
            var next = rev + 1;
            Exec(c, "UPDATE vault SET revision=$r, blob=$b, updated_utc=$t WHERE id=1", ("$r", next), ("$b", newBlobJson), ("$t", Now()));
            Exec(c, "DELETE FROM sessions");
            PruneHistoryTx(c);
            Exec(c, "COMMIT");
            return next;
        }
        catch { TryRollback(c); throw; }
    }

    public List<(long Revision, DateTime CreatedUtc)> ListHistory()
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT revision, created_utc FROM vault_history ORDER BY revision DESC";
        using var r = cmd.ExecuteReader();
        var list = new List<(long, DateTime)>();
        while (r.Read()) list.Add((r.GetInt64(0), Parse(r.GetString(1))));
        return list;
    }

    public HistoryRow? GetHistory(long revision)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT revision, blob, salt, kdf_memory, kdf_iter, kdf_par, created_utc FROM vault_history WHERE revision=$r";
        cmd.Parameters.AddWithValue("$r", revision);
        using var r = cmd.ExecuteReader();
        return r.Read() ? new HistoryRow(r.GetInt64(0), r.GetString(1), (byte[])r["salt"], new KdfDto(r.GetInt32(3), r.GetInt32(4), r.GetInt32(5)), Parse(r.GetString(6))) : null;
    }

    // ---------- sessions ----------

    public void CreateSession(byte[] tokenHash, TimeSpan absoluteLifetime)
    {
        using var c = Open();
        var now = _time.GetUtcNow().UtcDateTime;
        Exec(c, "DELETE FROM sessions WHERE expires_utc < $n", ("$n", now.ToString("O")));
        Exec(c, "INSERT INTO sessions (token_hash, created_utc, last_seen_utc, expires_utc) VALUES ($h,$c,$c,$e)",
            ("$h", tokenHash), ("$c", now.ToString("O")), ("$e", now.Add(absoluteLifetime).ToString("O")));
    }

    /// <summary>True if the session exists, has not passed its absolute expiry and was seen within <paramref name="idleTimeout"/>; then it is touched.</summary>
    public bool ValidateAndTouchSession(byte[] tokenHash, TimeSpan idleTimeout)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT last_seen_utc, expires_utc FROM sessions WHERE token_hash=$h";
        cmd.Parameters.AddWithValue("$h", tokenHash);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return false;
        var lastSeen = Parse(r.GetString(0));
        var expires = Parse(r.GetString(1));
        r.Close();

        var now = _time.GetUtcNow().UtcDateTime;
        if (now >= expires || now - lastSeen >= idleTimeout)
        {
            Exec(c, "DELETE FROM sessions WHERE token_hash=$h", ("$h", tokenHash));
            return false;
        }
        Exec(c, "UPDATE sessions SET last_seen_utc=$n WHERE token_hash=$h", ("$n", now.ToString("O")), ("$h", tokenHash));
        return true;
    }

    public void DeleteSession(byte[] tokenHash)
    {
        using var c = Open();
        Exec(c, "DELETE FROM sessions WHERE token_hash=$h", ("$h", tokenHash));
    }

    // ---------- transaction helpers ----------

    private static Account? ReadAccountTx(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT salt, kdf_memory, kdf_iter, kdf_par, auth_hash, auth_hash_salt FROM account WHERE id = 1";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new Account((byte[])r["salt"], new KdfDto(r.GetInt32(1), r.GetInt32(2), r.GetInt32(3)), (byte[])r["auth_hash"], (byte[])r["auth_hash_salt"]);
    }

    private static (long Revision, string Blob) ReadVaultTx(SqliteConnection c)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT revision, blob FROM vault WHERE id = 1";
        using var r = cmd.ExecuteReader();
        return r.Read() ? (r.GetInt64(0), r.GetString(1)) : (0, "");
    }

    private void SnapshotTx(SqliteConnection c, long revision, string blob, Account acct)
    {
        Exec(c, "INSERT OR REPLACE INTO vault_history (revision, blob, salt, kdf_memory, kdf_iter, kdf_par, created_utc) VALUES ($r,$b,$s,$m,$i,$p,$t)",
            ("$r", revision), ("$b", blob), ("$s", acct.Salt), ("$m", acct.Kdf.MemoryKiB), ("$i", acct.Kdf.Iterations), ("$p", acct.Kdf.Parallelism), ("$t", Now()));
    }

    private void PruneHistoryTx(SqliteConnection c)
    {
        Exec(c, "DELETE FROM vault_history WHERE revision NOT IN (SELECT revision FROM vault_history ORDER BY revision DESC LIMIT $n)", ("$n", _maxHistory));
    }

    private static void TryRollback(SqliteConnection c)
    {
        try { Exec(c, "ROLLBACK"); } catch { /* already rolled back or connection broken */ }
    }
}
