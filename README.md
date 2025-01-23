# Pydantic models for Nokia SR Linux

**This is an experiment.**

## Generation

```bash
# change the base repo dir path and the srl version
export SRL_YANG_REPO_PATH="${HOME}/projects/nokia/srlinux-yang-models"
export SRL_RELEASE_TAG="v24.10.1"
export PYDANTIFY_OUTPUT_DIR="${PWD}/models"

# no need to change these paths
export PYDANTIFY_LOOKUP_PATH="${SRL_YANG_REPO_PATH}/srlinux-yang-models"
export PYDANTIFY_IANA_PATH="${PYDANTIFY_LOOKUP_PATH}/iana"
export PYDANTIFY_IETF_PATH="${PYDANTIFY_LOOKUP_PATH}/ietf"
(cd ${SRL_YANG_REPO_PATH} && git checkout ${SRL_RELEASE_TAG})

export PYDANTIFY_SRL_MODELS_PATH="${SRL_YANG_REPO_PATH}/srlinux-yang-models/srl_nokia/models"

# temp dir
PYDANTIFY_TMP_DIR="./temp"
mkdir ${PYDANTIFY_TMP_DIR}

# copy all yang files from the srl repo to the temp dir
# traverse nested dirs and copy all *.yang files
find ${PYDANTIFY_SRL_MODELS_PATH} -name "*.yang" -exec cp {} ${PYDANTIFY_TMP_DIR} \;

#### generate the models
# interfaces
MODEL_SHORT_NAME="interfaces"
mkdir -p ./models/${MODE_SHORT_NAME}
pydantify \
${PYDANTIFY_TMP_DIR}/srl_nokia-${MODEL_SHORT_NAME}.yang \
-p ${PYDANTIFY_IANA_PATH} \
-p ${PYDANTIFY_IETF_PATH} \
-p ${PYDANTIFY_SRL_MODELS_PATH} \
-o ./models/${MODEL_SHORT_NAME} \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-dot1x.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-platform-healthz.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-ethcfm.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-ra_guard.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-packet-link-qual.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-nbr-evpn.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-l2cp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-ip-dhcp-relay.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-p4rt.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-dco.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-ip-vrrp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-router-adv.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-bridge-table-stp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-nbr-virtual-ip-discovery.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-bridge-table-mac-duplication-entries.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-bridge-table-statistics.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-ip-dhcp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-vlans.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-nbr.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-local-mirror-destination.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-lacp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-ip-dhcp-server.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-if-mpls.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-vxdp.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-bridge-table-mac-table.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-bridge-table-mac-learning-entries.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-lag.yang \
--deviation ${PYDANTIFY_TMP_DIR}/srl_nokia-interfaces-ethernet-segment-association.yang

# system
MODEL_SHORT_NAME="system"
mkdir -p ./models/${MODE_SHORT_NAME}
pydantify \
${PYDANTIFY_SRL_MODELS_PATH}/${MODEL_SHORT_NAME}/srl_nokia-${MODEL_SHORT_NAME}.yang \
-p ${PYDANTIFY_IANA_PATH} \
-p ${PYDANTIFY_IETF_PATH} \
-p ${PYDANTIFY_SRL_MODELS_PATH} \
-o ./models/${MODEL_SHORT_NAME}
```
