plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version("0.6.0")
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://jitpack.io")
        }
        maven("https://maven.walt.id/repository/waltid/")
    }
}

rootProject.name = "eudi-srv-web-verifier-endpoint-23220-4-kt"
