#
#  Called from the ci-scheduled-fuzzing.yml workflow to push back the merged
#  fuzzer corpus
#

import os
import base64

from github import Github

repo_env = os.environ["GITHUB_REPOSITORY"]
branch_env = os.environ["GITHUB_REF"]
token_env = os.environ["GITHUB_TOKEN"]

filename = os.environ["FILE"]
contents = base64.b64decode(os.environ["CONTENTS"])

print("About to commit update of " + filename + " to " + repo_env + ":" + branch_env)

gh = Github(token_env)
repo = gh.get_repo(repo_env)
fc = repo.get_contents(filename, branch_env)
repo.update_file(fc.path, "Scheduled fuzzing: Update " + fc.path, contents, fc.sha, branch=branch_env)

print("Committed")
