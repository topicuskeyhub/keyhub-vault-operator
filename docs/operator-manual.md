---
title: Topicus KeyHub Vault Operator
description: Operator Manual
---

## Overview

The keyhub-vault-operator uses a policy based mechanism to access KeyHub vault records. These policies are stored in a KeyHub vault themselves, the 'Policy Vault'. The client credentials in the `keyhub-vault-operator-secret` Secret are used to access the 'Policy Vault'. The 'Policy Vault' contains additional client credentials (username/secret fields) to be used to access the vaults containing the secrets to be synced to Kubernetes, based on policies defined in the comment field.

These KeyHub applications must have the Give access to accounts and setup of groups option ticked. The keyhub-vault-operator reads the groups the application is linked to. All vault records in the vaults of the linked groups are available in the KeyHubSecret CR.

```mermaid
sequenceDiagram
  participant operator as KeyHub Vault Operator
  participant ks as KeyHubSecret
  participant pv as Policy Vault
  participant pvr as Policy Vault Record
  participant sv as Secrets Vault
  participant svr as Secrets Vault Record
  participant k8s as Kubernetes API

  operator->>ks: Watch
  activate ks
  ks-->>operator: Reconcile
  deactivate ks

  operator->>pv: Connect with 'keyhub-vault-operator-secret' credentials
  activate pv
  pv->>pvr: Fetch client credentials by matching namespace of KeyHubSecret to policy
  activate pvr
  pvr-->>pv: Return associated client credentials
  deactivate pvr
  pv-->>operator: Return associated client credentials
  deactivate pv

  operator->>sv: Connect with associated client credentials from 'Policy Vault'
  activate sv
  loop
  sv->>svr: Fetch record based on KeyHubSecret
  activate svr
  svr-->>sv: Return record
  deactivate svr
  end
  sv-->>operator: Return records
  deactivate sv

  operator->>k8s: Reconcile Secret
  activate k8s
  k8s-->>operator: OK
  deactivate k8s
```

## Policy Vault access

The `keyhub-vault-operator-secret` Secret contains the following fields:
- **uri**: the url of your KeyHub instance
- **clientId**: KeyHub client application ID with access to the vault of your 'Policy Vault' KeyHub group
- **clientSecret**: KeyHub client application secret

## Policies

A policy defines a mapping between Kubernetes and a KeyHub OAuth2/OIDC application to be used to retrieve vault records. Currently only namespace-based policies defining a name (or a regex matching on the name) or a label selector are supported, e.g.:

```yaml
policies:
  - type: namespace
    name: default
  - type: namespace
    nameRegex: customer-.*
  - type: namespace
    labelSelector: field.cattle.io/projectId=p-xxxxx
```
