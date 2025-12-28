package com.sprintforge.apigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ApigatewayApplication {

    static void main(String[] args) {
        SpringApplication.run(ApigatewayApplication.class, args);
    }

}
