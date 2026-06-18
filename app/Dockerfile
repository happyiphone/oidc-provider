# Multi-stage build for the OIDC Provider API.
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
# Restore just the API project (it pulls in Core transitively) so the layer caches on csproj changes
# without needing the test/demo projects in the image.
COPY src/OidcProvider.Core/OidcProvider.Core.csproj src/OidcProvider.Core/
COPY src/OidcProvider.Api/OidcProvider.Api.csproj   src/OidcProvider.Api/
RUN dotnet restore src/OidcProvider.Api/OidcProvider.Api.csproj
COPY src/ src/
RUN dotnet publish src/OidcProvider.Api/OidcProvider.Api.csproj \
    -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
# The .NET runtime image already ships a non-root `app` user — just switch to it.
USER app
ENTRYPOINT ["dotnet", "OidcProvider.Api.dll"]
