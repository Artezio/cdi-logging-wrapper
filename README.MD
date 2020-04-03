CDI-LOGGING-WRAPPER

# Getting Started

1. Open your project's pom
2. Add a reference to the artezio mvn repository:
    ```xml
    <repository>
        <id>artezio</id>
        <url>https://nexus.artezio.net/repository/maven-releases</url>
    </repository>
    ```
2. Add the dependency:
    ```xml
    <dependency>
        <groupId>com.artezio.logging</groupId>
        <artifactId>cdi-logging-wrapper</artifactId>
        <version>1.0</version>
    </dependency>
    ```

# Usage

CDI-LOGGING-WRAPPER represents a cdi interceptor. To enable it add info about the class in `interceptors` section of `beans.xml`
```xml
<class>com.artezio.logging.LogInterceptor</class>
```
