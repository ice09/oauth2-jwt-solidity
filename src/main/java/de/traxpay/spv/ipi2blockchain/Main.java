package de.traxpay.spv.ipi2blockchain;

import de.traxpay.spv.ipi2blockchain.runner.IdentityContractDeployer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Main {

    private static IdentityContractDeployer IdentityContractDeployer;

    public static void main(String[] args) throws Exception {
        SpringApplication.run(Main.class, args);
    }

}
