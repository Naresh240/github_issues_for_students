#!/bin/bash
set -e

###############################################
# VARIABLES
###############################################
base_dir=$1           # Base directory
artifact_id=$2        # e.g. HOTSCAN_LMT_UAT
artifact_version=$3   # e.g. 25.4.4.6
release=$4            # e.g. HOTSCAN_LMT_25.4.4.6
build_label=$5        # e.g. 25.4.4.6.29
repo_name=$6          # e.g. mvn-private-local
group_id=$7           # e.g. com/db/hotscan
username=$8
password=$9

artifactory_url="https://artifactory.intranet.db.com/artifactory"

artifact_path="${base_dir}/${artifact_version}.tar.gz"
artifact_name=$(basename "$artifact_path")

# XML file instead of POM
xml_file="${base_dir}/${artifact_id}_${build_label}.xml"
metadata_path="${base_dir}/maven-metadata.xml"

###############################################
# FUNCTION: create_xml_file
###############################################
create_xml_file() {
  echo "Creating XML file at $xml_file ..."
  cat > "$xml_file" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<artifact>
  <groupId>${group_id}</groupId>
  <artifactId>${artifact_id}</artifactId>
  <version>${build_label}</version>
  <packaging>tar.gz</packaging>
  <description>Auto-generated XML for ${artifact_id}</description>
</artifact>
EOF
  echo "XML file created successfully."
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

  for file in "$artifact_path" "$xml_file" "$metadata_path"; do
    if [[ -f "$file" ]]; then
      filename=$(basename "$file")

      target_url="${artifactory_url}/${repo_name}/${group_id}/${artifact_id}/${release}/${build_label}/${filename}"

      echo "Uploading $filename to $target_url ..."
      http_status=$(curl -u "$username:$password" -T "$file" "${target_url}?override=1" -o /dev/null -s -w "%{http_code}")

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
}

###############################################
# MAIN EXECUTION
###############################################
if [[ ! -f "$artifact_path" ]]; then
  echo "Error: Artifact $artifact_path does not exist."
  exit 1
fi

create_xml_file
create_metadata_file
upload_to_artifactory

echo "All files uploaded successfully to Artifactory!"
