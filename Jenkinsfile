config {
	daysToKeep = 21
	cronTrigger = '@weekend'
}

def isMainBranch = env.BRANCH_NAME == 'main'
def releaseTags = []
if ( env.TAG_NAME && env.TAG_NAME.startsWith('v') ) {
  releaseTags << env.TAG_NAME
}

node() {
  catchError {
    git.checkout { }

    def img = dockerfile.build {
      name = "keyhub-vault-operator"
    }

    stage("Test") {
      docker.image("golang:1.15").inside() {
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
