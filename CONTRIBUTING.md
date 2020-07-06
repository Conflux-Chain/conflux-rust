# How to Contribute

Thank you for considering helping out Conflux. This document specifies rules
for proposing changes to Conflux protocol as well as Conflux-Rust
implementation. Note that we differentiate Conflux protocol and Conflux-Rust
implementation because we envision in the future there will be multiple implementations of
Conflux in different languages.

## Change Types

Code/protocol changes are classified into the following four different types.
Based on the type of the proposed change, it will go through slightly different
process.

**Backward Compatible Changes:** The updated client will be fully compatible with older versions. Such changes
may introduce additional RPC APIs or other new features. To submit a backward compatible change,
please follow this process:

* Fork the conflux-rust repository and submit a pull request.
* If it is a complicated change, please submit an [issue](https://github.com/Conflux-Chain/conflux-rust/issues) to communicate with the core devs first.

**Database/RPC Breaking Changes:** The updated client will be able to co-exist
with previous versions, but it updates the interface/behavior of an existing
RPC or it changes the blockchain database format. This would require
modifications for applications depending on these RPCs and/or clean up the
database to sync from the scratch. To submit a Database/RPC breaking change,
you can follow the above process but you have to submit an issue first.

**Protocol Breaking Changes:** These changes do not touch the specification of
the Conflux Protocol, but require an update to the P2P network protocol in
Conflux/Conflux-Rust. It is possible to enable the change without a hard-fork but
it would require special protocol version handling and compatibility testing.
To submit a protocol breaking change, please follow this process:

* Submit a Conflux Improvement Proposal ([CIP](https://github.com/Conflux-Chain/CIPs)) draft.
* Discuss the CIP until it is accepted. Note that in the CIP, it is important
to specify how the implementation can maintain compatibility with previous
protocol versions (via versioning or other techniques). If this cannot be done, the
change should be classified and treated as a spec breaking change instead.
* Create an issue in Conflux-Rust corresponding to the CIP.
* Submit a pull request implementing the CIP.
* Audit, test, and/or verify the implementation. The PR will be merged into the
master branch. The core developer team may choose to also merge the PR to other
branches for Conflux-Rust client releases.
* Once a release enables the change, update the CIP status to final.

**Spec Breaking Changes:** These changes require an update to the specification
of the Conflux protocol. It would require a hard-fork to enable the change. It
has no backward compatibility at all. The general process for making spec
breaking changes are:

* Submit a Conflux Improvement Proposal (CIP) draft. The draft should discuss how
to enable this change in a hard-fork.
* Discuss the CIP until it is accepted.
* Create an issue in the Conflux-Protocol repo corresponding to the CIP.
* Submit a pull request to the Conflux-Protocol repo to change the spec according to the CIP.
* Create an issue in the Conflux-Rust repo corresponding to the CIP.
* Submit a pull request implementing the CIP.
* Audit, test, and/or verify the implementation. The PR will be merged into the
master branch.
* Wait for a hard-fork to enable the change. Change the CIP status to final.

Note that now light client modes in Conflux-Rust are considered experimental. All changes that only affecting light clients will be considered as Backward Compatible for now.

## Submit an Issue

If you encounter a bug when running Conflux-Rust or you have enhancement suggestions, you are welcome to submit an issue. Note that Conflux-Rust is the full node client for Conflux. If you are experiencing bugs when using wallet, scan, etc., it is most likely a bug in these products rather than Conflux-Rust. Also note that for protocol/spec breaking changes, please create a CIP as well. Here is how issues will be managed:

* Submit a new issue. For bug reports, please provide steps as detailed as possible about how to *reproduce* this bug. If you have log files you can provide, that would be very helpful as well. For enhancement suggestions, please explain in details about the *motivation* of the proposed changes, i.e., how this change will help applications running on top of Conflux-Rust.
* One of the core development team members will be assigned to the issue to drive the discussion. After the discussion, the issue would be tagged with the "bug", "enhancement", or "wontchange" label. Issues tagged with the "wontchange" label will be closed within 7 days. For "bug" and "enhancement" issues, it will also receive a label to classify the estimated changes as "spec-breaking", "protocol-breaking", "database/rpc-breaking", and "backward compatible".
* If a PR is already submitted together with the Issue, then the PR will be reviewed by the assigned discussion lead. Once the PR is merged, this issue will be closed.
* If the issue needs the core development team to address, it will receive the label "need triage". A new core team member will be assigned as the implementation lead together with a priority label "P0", "P1", "P2", and "P3". Once the implementation PR has been developed and merged, the issue will be closed.

## Submit a Pull Request

We welcome your contribution to the Conflux-Rust repository. Here are the basic rules for submitting PRs.

* Pull requests need to be based on and opened against the `master` branch.
* Code must be formatted using [cargo_fmt.sh](https://github.com/Conflux-Chain/conflux-rust/blob/master/cargo_fmt.sh).
* We use reviewable.io as our code review tool for any pull request.
* If necessary, update CHANGELOG.md to document your changes.

## Submit a Conflux Improvement Proposal (CIP)

We have a separate repository to manage all CIPs. See [README](https://github.com/Conflux-Chain/CIPs/blob/master/README.md) in the repo.