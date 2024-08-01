plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version("0.6.0")

}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven {
            url = uri("https://jitpack.io")
        }

    }
}

rootProject.name = "eudi-srv-web-verifier-endpoint-23220-4-kt"

