# Smartling Keycloak Extras

Provides projects that may be useful when implementing Spring Security with [Keycloak].
These project may add auxiliary behavior or have yet to be merged into the Keycloak project.

## Modules

### Keycloak Spring Security Authentication

Provides an extension to Keycloak's Spring Security adapter that enables the authentication
via direct access grants.

### Keycloak Spring Security User Details

Provides an extension to Keycloak's Spring Security adapter that enables the authenticated
principal to be loaded from a Spring Security user detail service.

### Usage

[ ![Download](https://api.bintray.com/packages/smartling/release/keycloak-spring-security-auth/images/download.svg) ](https://bintray.com/smartling/release/keycloak-spring-security-auth/_latestVersion)

```
<dependency>
	<groupId>com.smartling.keycloak.extras</groupId>
	<artifactId>keycloak-spring-security-auth</artifactId>
	<version>${version}</version>
</dependency>

<dependency>
	<groupId>com.smartling.keycloak.extras</groupId>
	<artifactId>keycloak-spring-security-user-details</artifactId>
	<version>${version}</version>
</dependency>

```

## Using Smartling Keycloak Extras



Smartling Keycloak Extras are now distributed via [JCenter]. Simply add JCenter as repository in your build.

[jcenter]: https://bintray.com/bintray/jcenter
[keycloak]: http://keycloak.org
[repo]: https://dl.bintray.com/smartling/release


##Destribution to github through site-maven-plugin

GITHUB_USER, GITHUB_KEY should be provided as env variables

mvn deploy -s settings.xml -DskipTests

#usage

Simply add to ```repositories``` in your pom.xml

```
 <repository>
    <id>smartling-keycloak-extras-mvn-repo</id>
    <url>https://raw.github.com/GITHUB_USER/smartling-keycloak-extras/mvn-repo</url>
    <snapshots>
        <enabled>true</enabled>
        <updatePolicy>always</updatePolicy>
    </snapshots>
</repository>

```

