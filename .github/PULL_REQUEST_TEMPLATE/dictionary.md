---
name: Dictionary updates
about: Used to submit changes for vendor dictionaries or standards dictionaries
---

# Dictionary updates

For dictionary changes please open pull requests for both the `master` and
`v3.0.x` branches following the submission checklists below.

*Note: The attribute referencing syntax in `master` has changed.  When
referencing nested attributes such as VSAs or TLVs the complete path is used.
The reference string for the `Option-Request` attribute in the example below
would be `Vendor-Specific.CableLabs.Option-Request`.  This is why attribute
prefixes are NOT used in the `master` branch.*

## Submission checklist `master` branch

- [ ] Vendor prefix ***NOT*** added for `vendor` attributes

**Good**
```text
VENDOR          CableLabs                       4491
BEGIN-VENDOR    CableLabs
ATTRIBUTE       Option-Request                  1       octets
```
**Bad**
```text
VENDOR          CableLabs                       4491
BEGIN-VENDOR    CableLabs
ATTRIBUTE       CableLabs-Option-Request        1       octets
```
- [ ] Parent prefix ***NOT*** added for `tlv` attributes

**Good**
```text
ATTRIBUTE DPSK-Params                           153     tlv
ATTRIBUTE AKM-Suite                             .1      octets
ATTRIBUTE Cipher                                .2      byte
ATTRIBUTE Anonce                                .3      octets
ATTRIBUTE EAPOL-Key-Frame                       .4      octets
```
**Bad**
```text
ATTRIBUTE DPSK-Params                           153     tlv
ATTRIBUTE DPSK-Params-AKM-Suite                 .1      octets
ATTRIBUTE DPSK-Params-Cipher                    .2      byte
ATTRIBUTE DPSK-Params-Anonce                    .3      octets
ATTRIBUTE DPSK-Params-EAPOL-Key-Frame           .4      octets
```
- [ ] Dictionary tested by starting the server with the new dictionary loaded (`radiusd -C`).
- [ ] Dictionary run through [format.pl](https://github.com/FreeRADIUS/freeradius-server/blob/master/scripts/dict/format.pl) (`scripts/dict/format.pl <path to dictionary>`).
- [ ] **New dictionaries only** - Dictionary added to the include list in the top level `dictionary` file of the protocol dictionary.


## Submission checklist `v3.0.x` branch
- [ ] Vendor prefix added for `vendor` attributes

**Good**
```text
VENDOR          CableLabs                       4491
BEGIN-VENDOR    CableLabs
ATTRIBUTE       CableLabs-Option-Request        1       octets
```
**Bad**
```text
VENDOR          CableLabs                       4491
BEGIN-VENDOR    CableLabs
ATTRIBUTE       Option-Request                  1       octets
```

- [ ] Parent prefix added for `tlv` attributes

**Good**
```text
ATTRIBUTE DPSK-Params                           153     tlv
ATTRIBUTE DPSK-Params-AKM-Suite                 .1      octets
ATTRIBUTE DPSK-Params-Cipher                    .2      byte
ATTRIBUTE DPSK-Params-Anonce                    .3      octets
ATTRIBUTE DPSK-Params-EAPOL-Key-Frame           .4      octets
```
**Bad**
```text
ATTRIBUTE DPSK-Params                           153     tlv
ATTRIBUTE AKM-Suite                             .1      octets
ATTRIBUTE Cipher                                .2      byte
ATTRIBUTE Anonce                                .3      octets
ATTRIBUTE EAPOL-Key-Frame                       .4      octets
```
- [ ] Dictionary tested by starting the server with the new dictionary loaded (`radiusd -C`).
- [ ] Dictionary run through [format.pl](https://github.com/FreeRADIUS/freeradius-server/blob/v3.0.x/share/format.pl) (`share/format.pl <path to dictionary>`).
- [ ] **New dictionaries only** - Dictionary added to the include list in the top level `dictionary` file of the protocol dictionary.
