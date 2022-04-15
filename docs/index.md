---
title: "Topicus KeyHub Vault Operator"
---

![Topicus KeyHub](/keyhub-vault-operator/assets/keyhub.png)

## Overview

Use this Kubernetes operator to synchronize secrets stored in Topicus KeyHub vaults and Kubernetes `Secret` resources. A special `KeyHubSecret` resource defines a mapping between a Kubernetes `Secret` and one or more vault records defined in Topicus KeyHub.

## Operator Manual

To learn about setting up the operator and allowing it access to Topicus KeyHub read the [operator manual](operator-manual.md).

## User Guide

The [user guide](user-guide.md) explains how to define all kind of mappings between vault records and Kubernetes `Secret` resources using the `KeyHubSecret` resource.
