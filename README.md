# oss-maven-template

![GitHub release (with filter)](https://img.shields.io/github/v/release/sentrysoftware/oss-maven-template)
![Build](https://img.shields.io/github/actions/workflow/status/sentrysoftware/oss-maven-template/deploy.yml)
![GitHub top language](https://img.shields.io/github/languages/top/sentrysoftware/oss-maven-template)
![License](https://img.shields.io/github/license/sentrysoftware/oss-maven-template)

Repository template for all Sentry open-source Java projects, published on Maven Central.

## Build instructions

This is a simple Maven project. Build with:

```bash
mvn verify
```

## Release instructions

The artifact is deployed to Sonatype's [Maven Central](https://central.sonatype.com/).

The actual repository URL is https://s01.oss.sonatype.org/, with server Id `ossrh` and requires credentials to deploy
artifacts manually.

But it is strongly recommended to only use [GitHub Actions "Release to Maven Central"](actions/workflows/release.yml) to perform a release:

* Manually trigger the "Release" workflow
* Specify the version being released and the next version number (SNAPSHOT)
* Release the corresponding staging repository on [Sonatype's Nexus server](https://s01.oss.sonatype.org/)
* Merge the PR that has been created to prepare the next version

## License

License is Apache-2. Each source file must include the Apache-2 header (build will fail otherwise).
To update source files with the proper header, simply execute the below command:

```bash
mvn license:update-file-header
```
