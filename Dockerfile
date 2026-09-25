# Build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/ src/
RUN dotnet publish src/Server -c Release -o /app --no-self-contained

# Runtime: non-root, only the published app and a /data volume
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
RUN mkdir /data && chown 1654:1654 /data
ENV RVS_DATADIR=/data \
    ASPNETCORE_URLS=http://+:8080 \
    DOTNET_EnableDiagnostics=0
USER 1654
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["dotnet", "RhodiumVaultServer.dll"]
