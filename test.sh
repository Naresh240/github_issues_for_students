#!/bin/bash
set -e

###############################################
# VARIABLES
###############################################
base_dir=$1
artifact_id=$2
artifact_version=$3
release=$4
build_label=$5
repo_name=$6
group_id=$7
username=$8
password=$9

artifactory_url="https://artifactory.intranet.db.com/artifactory"

artifact_path="${base_dir}/${artifact_version}.tar.gz"
pom_file="${base_dir}/${artifact_version}.pom"
metadata_path="${base_dir}/maven-metadata.xml"

###############################################
# FUNCTION: create_pom_file
###############################################
create_pom_file() {
  echo "Creating POM file at $pom_file ..."
  cat > "$pom_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
                             http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>${group_id}</groupId>
  <artifactId>${artifact_id}</artifactId>
  <version>${artifact_version}</version>
  <packaging>tar.gz</packaging>
  <description>Auto-generated POM for ${artifact_id}</description>
</project>
EOF
  echo "POM file created successfully."
}

###############################################
# FUNCTION: create_metadata_file
###############################################
create_metadata_file() {
  echo "Creating maven-metadata.xml at $metadata_path ..."
  cat > "$metadata_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>${group_id}</groupId>
  <artifactId>${artifact_id}</artifactId>
  <versioning>
    <latest>${artifact_version}</latest>
    <release>${artifact_version}</release>
    <versions>
      <version>${artifact_version}</version>
    </versions>
    <lastUpdated>$(date +"%Y%m%d%H%M%S")</lastUpdated>
  </versioning>
</metadata>
EOF
  echo "maven-metadata.xml created successfully."
}

###############################################
# FUNCTION: upload_to_artifactory
###############################################
upload_to_artifactory() {
  echo "Starting upload to Artifactory..."

  # Maven-compliant path: groupId converted to folder path
  base_release_target="${artifactory_url}/${repo_name}/${group_id//.//}/${artifact_id}/${release}"
  build_target="${base_release_target}/${build_label}"

  # Upload tar.gz and pom under build_label folder
  for file in "$artifact_path" "$pom_file"; do
    if [[ -f "$file" ]]; then
      filename=$(basename "$file")
      target_url="${build_target}/${filename}?override=1"

      echo "Uploading $filename to $target_url ..."
      http_status=$(curl -u "$username:$password" -T "$file" \
        -o /dev/null -s -w "%{http_code}" "$target_url")

      if [[ "$http_status" -ne 200 && "$http_status" -ne 201 ]]; then
        echo "Upload failed for $filename (HTTP $http_status)"
        # Only warn if pom fails (don’t stop pipeline)
        if [[ "$filename" == *.pom ]]; then
          echo "Skipping POM upload failure; continuing..."
        else
          exit 1
        fi
      else
        echo "$filename uploaded successfully (HTTP $http_status)"
      fi
    else
      echo "File not found: $file — skipping..."
    fi
  done

  # Upload maven-metadata.xml at release level
  if [[ -f "$metadata_path" ]]; then
    echo "Uploading maven-metadata.xml to $base_release_target ..."
    http_status=$(curl -u "$username:$password" -T "$metadata_path" \
      -o /dev/null -s -w "%{http_code}" "${base_release_target}/maven-metadata.xml?override=1")

    if [[ "$http_status" -ne 200 && "$http_status" -ne 201 ]]; then
      echo "Upload failed for maven-metadata.xml (HTTP $http_status)"
    else
      echo "maven-metadata.xml uploaded successfully (HTTP $http_status)"
    fi
  fi
}

###############################################
# MAIN EXECUTION
###############################################
if [[ $# -lt 9 ]]; then
  echo "Usage: $0 <base_dir> <artifact_id> <artifact_version> <release> <build_label> <repo_name> <group_id> <username> <password>"
  exit 1
fi

if [[ ! -f "$artifact_path" ]]; then
  echo "Error: Artifact $artifact_path does not exist."
  exit 1
fi

create_pom_file
create_metadata_file
upload_to_artifactory

echo "All files uploaded successfully to Artifactory!"
