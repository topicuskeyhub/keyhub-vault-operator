#!/usr/bin/env node
const { execSync } = require( "child_process" );
exports.preCommit = ( props ) =>
{
  const version = props.version
  command = `yq eval -i '.images[0].newTag = "${ version }" ' ./config/manager/kustomization.yaml`
  execSync( command )
}