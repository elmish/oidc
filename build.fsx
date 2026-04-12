#!/usr/bin/env -S dotnet fsi
#r "nuget: Fake.Core.Target, 5.23.1"
#r "nuget: Fake.IO.FileSystem, 5.23.1"
#r "nuget: Fake.DotNet.Cli, 5.23.1"
#r "nuget: Fake.Core.ReleaseNotes, 5.23.1"
#r "nuget: Fake.Tools.Git, 5.23.1"
#r "nuget: MSBuild.StructuredLogger, 2.2.441"

open Fake.Core
open Fake.Core.TargetOperators
open Fake.DotNet
open Fake.Tools
open Fake.IO
open Fake.IO.FileSystemOperators
open Fake.IO.Globbing.Operators
open System
open System.IO

let gitName = "OIDC"
let gitOwner = "elmish"
let gitHome = sprintf "https://github.com/%s" gitOwner
let gitRepo = sprintf "git@github.com:%s/%s" gitOwner gitName

let projects  =
      !! "src/**.fsproj"
      ++ "netstandard/**.fsproj"
      ++ "reactnative/**.fsproj"

System.Environment.GetCommandLineArgs()
|> Array.skip 2 // fsi.exe; build.fsx
|> Array.toList
|> Context.FakeExecutionContext.Create false __SOURCE_FILE__
|> Context.RuntimeContext.Fake
|> Context.setExecutionContext

Target.create "Clean" (fun _ ->
    !! "**/obj"
    ++ "**/bin"
    -- "node_modules/**"
    |> Shell.cleanDirs
)

Target.create "Restore" (fun _ ->
    projects
    |> Seq.iter (Path.GetDirectoryName >> DotNet.restore id)
)

Target.create "Build" (fun _ ->
    projects
    |> Seq.iter (Path.GetDirectoryName >> DotNet.build id)
)

let release = ReleaseNotes.load "RELEASE_NOTES.md"

Target.create "Meta" (fun _ ->
    $"""
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <None Include="$(MSBuildThisFileDirectory)/LICENSE.md" Pack="true" PackagePath="\" />
    <None Include="$(MSBuildThisFileDirectory)/README.md" Pack="true" PackagePath="\"/>
    <PackageReference Include="Microsoft.SourceLink.GitHub" PrivateAssets="All"/>
  </ItemGroup>
  <PropertyGroup>
    <EmbedUntrackedSources>true</EmbedUntrackedSources>
    <AllowedOutputExtensionsInPackageBuildOutputFolder>$(AllowedOutputExtensionsInPackageBuildOutputFolder);.pdb</AllowedOutputExtensionsInPackageBuildOutputFolder>
    <Description>oAuth2/OIDC client for Elmish apps</Description>
    <PackageProjectUrl>https://github.com/{gitOwner}/{gitName}</PackageProjectUrl>
    <PackageLicenseFile>LICENSE.md</PackageLicenseFile>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <RepositoryUrl>{gitHome}/{gitName}</RepositoryUrl>
    <PackageTags>fable;elmish;fsharp;oAuth2;OIDC</PackageTags>
    <PackageReleaseNotes>{List.head release.Notes}</PackageReleaseNotes>
    <Authors>Eugene Tolmachev</Authors>
    <Version>{string release.SemVer}</Version>
  </PropertyGroup>
</Project>"""
    |> List.singleton
    |> File.write false "Directory.Build.props"
)

Target.create "Package" (fun _ ->
    projects
    |> Seq.iter (Path.GetDirectoryName >> DotNet.pack id)
)

Target.create "PublishNuget" (fun _ ->
    let nugetKey = Environment.environVar "nugetkey"
    let ver = string release.SemVer
    let push dir pkg =
        let exec = DotNet.exec (DotNet.Options.withWorkingDirectory dir)
        let result = exec "nuget" $"push {pkg}.{ver}.nupkg -s nuget.org -k {nugetKey}"
        if (not result.OK) then failwithf "%A" result.Errors

    push "src/bin/Release" "Fable.Elmish.OIDC"
    push "netstandard/bin/Release" "Elmish.OIDC"
    push "reactnative/bin/Release" "Fable.Elmish.OIDC.ReactNative"
)

Target.create "Publish" ignore

// Build order
"Clean"
    ==> "Meta"
    ==> "Restore"
    ==> "Build"
    ==> "Package"
    ==> "PublishNuget"
    ==> "Publish"

// start build
Target.runOrDefault "Build"
