FROM microsoft/aspnetcore-build

RUN mkdir -p /sso/published
WORKDIR /sso


# copy project.json and restore as distinct layers
COPY project.json .
RUN dotnet restore

# copy and build everything else
COPY . .
RUN dotnet publish --configuration Release --output published
ENTRYPOINT ["dotnet", "published/sso.dll"]
