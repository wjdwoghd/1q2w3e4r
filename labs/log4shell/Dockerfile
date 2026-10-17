FROM maven:3.9.11-eclipse-temurin-17 AS build
ARG LAB_VARIANT
WORKDIR /build
COPY pom.xml ./pom.xml
COPY common/ ./common/
COPY vulnerable/pom.xml ./vulnerable/pom.xml
COPY patched/pom.xml ./patched/pom.xml
RUN case "$LAB_VARIANT" in vulnerable|patched) ;; *) exit 2 ;; esac \
    && mvn -B -f "$LAB_VARIANT/pom.xml" clean package \
    && cp -a "$LAB_VARIANT/target/runtime" /runtime

FROM eclipse-temurin:17-jre-noble
WORKDIR /opt/lab
COPY --from=build --chown=10001:10001 /runtime/ ./runtime/
ENV LAB_CONTAINER=1
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --start-period=10s --retries=10 \
  CMD ["java", "-cp", "/opt/lab/runtime/classes:/opt/lab/runtime/lib/*", "com.example.sbomlab.BankingLab", "--healthcheck"]
ENTRYPOINT ["java", "-cp", "/opt/lab/runtime/classes:/opt/lab/runtime/lib/*", "com.example.sbomlab.BankingLab", "--host", "0.0.0.0", "--port", "8080"]
