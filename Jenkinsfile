def isPrimaryBranch = env.BRANCH_IS_PRIMARY
def releaseTags = []
if ( env.TAG_NAME && env.TAG_NAME.startsWith("v") ) {
  releaseTags << env.TAG_NAME.substring(1)
}

config {
  daysToKeep = 21
  cronTrigger = isPrimaryBranch ? "@weekend" : ""
}

node() {
  catchError {
    git.checkout { }

    def img = dockerfile.build {
      name = "keyhub-vault-operator"
    }

    stage("Test") {
      def kubebuilder = docker.build("kubebuilder-${env.BUILD_ID}", "-f Dockerfile.test .")
      kubebuilder.inside() {
        sh("make test")
      }
    }
    
    if (isPrimaryBranch || releaseTags) {
      dockerfile.publish {
        image = img
        baseTag = false
        latestTag = isPrimaryBranch
        tags = releaseTags
        distribute = true
      }
    }
  }

  notify { slackChannel = "#jenkins-job-results" }
}
