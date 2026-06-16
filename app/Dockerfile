# Multi-stage build for the OIDC Provider API.
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY OidcProvider.sln .
COPY src/OidcProvider.Core/OidcProvider.Core.csproj src/OidcProvider.Core/
COPY src/OidcProvider.Api/OidcProvider.Api.csproj   src/OidcProvider.Api/
RUN dotnet restore
COPY . .
RUN dotnet publish src/OidcProvider.Api/OidcProvider.Api.csproj \
    -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
# Run as non-root.
RUN adduser --disabled-password --gecos "" app && chown -R app /app
USER app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "OidcProvider.Api.dll"]
