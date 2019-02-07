.PHONY: test package pytest pylinttest clean openapi

export USER
PKG_NAME=py_insightvm_sdk
PKG_NAME_EGG:=$(subst -,_,$(PKG_NAME))
PKG_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
export PYTHONPATH:=$(shell pwd):$(shell pwd)/$(PKG_NAME):$(PATH)

all:
	@echo "Version: $(PKG_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@echo 'the only available options are: openapi, clean' || false

clean:
	@find . -name \*.pyc -delete
	@rm -rf dist/

openapi:
	@mkdir -p ./${PKG_NAME}/client
	@java -jar ../../swagger-api/swagger-codegen/modules/swagger-codegen-cli/target/swagger-codegen-cli.jar \
		generate \
		-DpackageName=${PKG_NAME} \
		-i ./assets/openapi.json -l python -o ./
