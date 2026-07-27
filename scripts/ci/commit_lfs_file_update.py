#
#  Called from the ci-scheduled-fuzzing.yml workflow to push back the merged
#  fuzzer corpus
#

import os
import base64

from github import Github
from github import Auth
from github.GithubException import UnknownObjectException

repo_env = os.environ["GITHUB_REPOSITORY"]
branch_env = os.environ["GITHUB_REF"]
token_env = os.environ["APP_TOKEN"]

filename = os.environ["FILE"]
contents = base64.b64decode(os.environ["CONTENTS"])

print("About to commit update of " + filename + " to " + repo_env + ":" + branch_env)

auth = Auth.Token(token_env)
gh = Github(auth=auth)
repo = gh.get_repo(repo_env)

try:
	fc = repo.get_contents(filename, branch_env)
	repo.update_file(fc.path, "Scheduled fuzzing: Update " + fc.path, contents, fc.sha, branch=branch_env)
except UnknownObjectException:
	repo.create_file(filename, "Scheduled fuzzing: Add " + filename, contents, branch=branch_env)

print("Committed")
