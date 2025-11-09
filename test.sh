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
artifact_name=$(basename "$artifact_path")

pom_file="${base_dir}/${artifact_id}-${artifact_version}.pom"
metadata_path="${base_dir}/maven-metadata.xml"
script_file="${base_dir}/upload_to_artifactory.sh"

###############################################
# FUNCTION: create_pom_file
###############################################
create_pom_file() {
  echo "Creating POM file at $pom_file ..."
  cat > "$pom_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
                              http://maven.apache.org/xsd/maven-4.0.0.xsd"
         xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
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
  <version>${artifact_version}</version>
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

  for file in "$artifact_path" "$pom_file" "$metadata_path"; do
    if [[ -f "$file" ]]; then
      filename=$(basename "$file")
      target_url="${artifactory_url}/${repo_name}/${group_id}/${artifact_id}/${release}/${build_label}/${filename}"

      echo "Uploading $filename to $target_url ..."
      http_status=$(curl -u "$username:$password" \
        -H "X-Checksum-Deploy: false" \
        -T "$file" "$target_url" -o /dev/null -s -w "%{http_code}")

      if [[ "$http_status" -ne 200 && "$http_status" -ne 201 ]]; then
        echo "Upload failed for $filename (HTTP $http_status)"
        exit 1
      else
        echo "$filename uploaded successfully (HTTP $http_status)"
      fi
    else
      echo "File not found: $file — skipping..."
    fi
  done

  ###############################################
  # Upload this script itself
  ###############################################
  if [[ -f "$script_file" ]]; then
    script_name=$(basename "$script_file")
    script_target="${artifactory_url}/${repo_name}/${group_id}/${artifact_id}/${release}/${build_label}/${script_name}"

    echo "Uploading $script_name to $script_target ..."
    http_status=$(curl -u "$username:$password" \
      -H "X-Checksum-Deploy: false" \
      -T "$script_file" "$script_target" -o /dev/null -s -w "%{http_code}")

    if [[ "$http_status" -ne 200 && "$http_status" -ne 201 ]]; then
      echo "Upload failed for $script_name (HTTP $http_status)"
      exit 1
    else
      echo "$script_name uploaded successfully (HTTP $http_status)"
    fi
  else
    echo "Script file not found: $script_file — skipping upload."
  fi
}

###############################################
# MAIN EXECUTION
###############################################
if [[ ! -f "$artifact_path" ]]; then
  echo "Error: Artifact $artifact_path does not exist."
  exit 1
fi

create_pom_file
create_metadata_file
upload_to_artifactory

echo "✅ All files (artifact, POM, metadata, and script) uploaded successfully to Artifactory — overwrite allowed!"
