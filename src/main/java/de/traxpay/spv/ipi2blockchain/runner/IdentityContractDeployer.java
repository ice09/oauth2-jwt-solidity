package de.traxpay.spv.ipi2blockchain.runner;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import de.ice09.jwt.Identity;
import de.ice09.jwt.JWKS;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.web3j.abi.EventEncoder;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.gas.StaticGasProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class IdentityContractDeployer implements CommandLineRunner {

    public static final String pkDeployer           = "710404145A788A5F2B7B6678F894A8BA621BDF8F4C04B44A3F703159916D39DF";
    public static final String pkAddress            = "5f5a6b061513e1b3a1600cffec2b9e18915c8e66f17a28c07bb3337a354fc8d8";

    private Web3j httpWeb3;

    private Credentials credDeployerIdentity;
    private Credentials credRecoveryAddress;
    private Identity identityContractHttp;

    @Autowired
    private TokenCreator tokenCreator;
    private JWKS jwksContractHttp;

    private boolean keyset;
    private boolean recovered;
    private String[] tokenAsBase64;

    @Override
    public void run(String... args) throws Exception {
        credDeployerIdentity = Credentials.create(pkDeployer);
        credRecoveryAddress = Credentials.create(pkAddress);
        connectToLocalBlockchain();
        extractTokenAsBase64();
        deployIdentityContractToBlockchain();
        addEventListenerForContractEvents();
        recoverNewAddressForSubject();
    }

    private void connectToLocalBlockchain() throws IOException {
        httpWeb3 = Web3j.build(new HttpService("http://127.0.0.1:8545", createOkHttpClient()));
        BigInteger balance = httpWeb3.ethGetBalance(credDeployerIdentity.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance();
        log.info("Deployer address " + credDeployerIdentity.getAddress() + " has " + balance + " wei.");
    }

    private String getModulusFromCertificates() throws IOException {
        DocumentContext jsonContext = JsonPath.parse(new URL(tokenCreator.getKeycloakCertUrl()));
        return jsonContext.read("$['keys'][0]['n']");
    }

    private void extractTokenAsBase64() {
        AuthenticationDataDto dto = tokenCreator.retrieveToken();
        tokenAsBase64 = dto.getAccess_token().split("\\.");
    }

    private void deployIdentityContractToBlockchain() throws Exception {
        jwksContractHttp = JWKS.deploy(httpWeb3, credDeployerIdentity, new StaticGasProvider(DefaultGasProvider.GAS_PRICE, DefaultGasProvider.GAS_LIMIT)).send();
        log.info("Deployed jwks contract at " + jwksContractHttp.getContractAddress());

        DocumentContext jsonContext = JsonPath.parse(new String(Base64.getUrlDecoder().decode(tokenAsBase64[1])));
        String subjectFromToken = jsonContext.read("$['sub']");

        identityContractHttp = Identity.deploy(httpWeb3, credDeployerIdentity, new StaticGasProvider(DefaultGasProvider.GAS_PRICE, DefaultGasProvider.GAS_LIMIT), BigInteger.ZERO, subjectFromToken, jwksContractHttp.getContractAddress()).send();
        // load contract again with different credentials to simulate calling not from deployer address
        // Important: set higher gas (x10), otherwise RSA sig check will fail!
        identityContractHttp = Identity.load(identityContractHttp.getContractAddress(), httpWeb3, credRecoveryAddress, new StaticGasProvider(BigInteger.valueOf(22000000000L), BigInteger.valueOf(65000000L)));
    }

    private void addEventListenerForContractEvents() {
        EthFilter filterIdentity = new EthFilter(DefaultBlockParameterName.LATEST, DefaultBlockParameterName.LATEST, identityContractHttp.getContractAddress());
        String encodedEventSignature = EventEncoder.encode(Identity.RECOVERED_EVENT);
        EthFilter filterJwks = new EthFilter(DefaultBlockParameterName.LATEST, DefaultBlockParameterName.LATEST, jwksContractHttp.getContractAddress());
        String encodedEventSignatureJwks = EventEncoder.encode(JWKS.KEYSET_EVENT);
        filterIdentity.addSingleTopic(encodedEventSignature);
        filterJwks.addSingleTopic(encodedEventSignatureJwks);
        jwksContractHttp.kEYSETEventFlowable(filterJwks).subscribe(event -> { log.info("Key successfully set to " + Hex.toHexString(event._modulus)); keyset = true; } );
        identityContractHttp.rECOVEREDEventFlowable(filterIdentity).subscribe(event -> { log.info(event._sub + " added address " + event._sender); recovered = true; } );
    }

    public void recoverNewAddressForSubject() throws Exception {
        String fromUrl = getModulusFromCertificates();
        byte[] modulus = Base64.getUrlDecoder().decode(fromUrl);

        TransactionReceipt recpKey = jwksContractHttp.setKey(modulus).send();
        while (!keyset) {
            log.info("Waiting for key to be set in transaction " + recpKey.getTransactionHash());
            Thread.sleep(5000);
        }

        TransactionReceipt recp = identityContractHttp.recover(
                new String(Base64.getUrlDecoder().decode(tokenAsBase64[0]), StandardCharsets.ISO_8859_1),
                new String(Base64.getUrlDecoder().decode(tokenAsBase64[1]), StandardCharsets.ISO_8859_1),
                Base64.getUrlDecoder().decode(tokenAsBase64[2])).send();

        while (!recovered) {
            log.info("Waiting for recovering address in transaction " + recp.getTransactionHash());
            Thread.sleep(5000);
        }

    }

    private OkHttpClient createOkHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        configureTimeouts(builder);
        return builder.build();
    }

    private void configureTimeouts(OkHttpClient.Builder builder) {
        Long tos = 3000L;
        builder.connectTimeout(tos, TimeUnit.SECONDS);
        builder.readTimeout(tos, TimeUnit.SECONDS);  // Sets the socket timeout too
        builder.writeTimeout(tos, TimeUnit.SECONDS);
    }


}