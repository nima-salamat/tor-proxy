pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven {
            name = "GuardianProject"
            url = uri("https://raw.githubusercontent.com/guardianproject/gpmaven/master")
            content {
                includeGroup("info.guardianproject")
            }
        }
    }
}

rootProject.name = "TorProxyAndroid"
include(":app")
