# Pydantic models for Nokia SR Linux

Experimental.

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

#### generate the models
# interfaces
MODEL_SHORT_NAME="interfaces"
mkdir -p ./models/${MODE_SHORT_NAME}
pydantify \
${PYDANTIFY_SRL_MODELS_PATH}/${MODEL_SHORT_NAME}/srl_nokia-${MODEL_SHORT_NAME}.yang \
-p ${PYDANTIFY_IANA_PATH} \
-p ${PYDANTIFY_IETF_PATH} \
-p ${PYDANTIFY_SRL_MODELS_PATH} \
-o ./models/${MODEL_SHORT_NAME}

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
