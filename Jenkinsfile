def isMainBranch = env.BRANCH_NAME == "main"
def releaseTags = []
if ( env.TAG_NAME && env.TAG_NAME.startsWith("v") ) {
  releaseTags << env.TAG_NAME
}

config {
  daysToKeep = 21
  cronTrigger = isMainBranch || releaseTags ? "weekend" : ""
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
    
    if (isMainBranch || releaseTags) {
      dockerfile.publish {
        image = img
        baseTag = false
        latestTag = isMainBranch
        tags = releaseTags
        distribute = true
      }
    }
  }

  notify { slackChannel = "#jenkins-job-results" }
}
