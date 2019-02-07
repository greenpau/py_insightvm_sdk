# Developer Notes

First, install OpenJDK:

```bash
yum -y install java-1.8.0-openjdk
echo "export JAVA_HOME=/usr/lib/jvm/jre-1.8.0-openjdk/" > /etc/profile.d/java_home.sh
```

Next, install Maven:

```bash
MVN_DIR=/usr/lib/mvn
MVN_VERSION=3.6.0
mkdir -p ${MVN_DIR}
cd ${MVN_DIR}
curl --silent \
  http://mirror.cc.columbia.edu/pub/software/apache/maven/maven-3/${MVN_VERSION}/binaries/apache-maven-${MVN_VERSION}-bin.tar.gz \
  --output apache-maven-${MVN_VERSION}-bin.tar.gz
tar xvzf apache-maven-${MVN_VERSION}-bin.tar.gz
ln -sf ${MVN_DIR}/apache-maven-${MVN_VERSION}/bin/mvn /usr/local/bin/mvn
/usr/local/bin/mvn -v
cat <<EOF > /etc/profile.d/apache-maven.sh
export M2_HOME=${MVN_DIR}/apache-maven-${MVN_VERSION}
export M2=\$M2_HOME/bin
export MAVEN_OPTS="-Xmx1024m"
EOF
```

Then, download `swagger-codegen` and use Maven to build it:

```bash
mkdir -p ~/dev/github.com/swagger-api
cd ~/dev/github.com/swagger-api
git clone https://github.com/swagger-api/swagger-codegen
cd swagger-codegen
mvn clean package
```

Next, switch to `py_insightvm_sdk` and generate a client library:

```bash
make openapi
```
