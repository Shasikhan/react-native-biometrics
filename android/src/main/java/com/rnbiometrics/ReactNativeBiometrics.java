package com.rnbiometrics;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.AuthenticationCallback;
import androidx.biometric.BiometricPrompt.PromptInfo;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;

/**
 * Created by brandon on 4/5/18.
 */

public class ReactNativeBiometrics extends ReactContextBaseJavaModule {

    protected String biometricKeyAlias = "biometric_key";

    public ReactNativeBiometrics(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "ReactNativeBiometrics";
    }

    @ReactMethod
    public void isSensorAvailable(final ReadableMap params, final Promise promise) {
        try {
            if (isCurrentSDKMarshmallowOrLater()) {
                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");
                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                int canAuthenticate = biometricManager.canAuthenticate(getAllowedAuthenticators(allowDeviceCredentials));

                if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", true);
                    resultMap.putString("biometryType", "Biometrics");
                    promise.resolve(resultMap);
                } else {
                    WritableMap resultMap = new WritableNativeMap();
                    resultMap.putBoolean("available", false);

                    switch (canAuthenticate) {
                        case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NO_HARDWARE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                            resultMap.putString("error", "BIOMETRIC_ERROR_HW_UNAVAILABLE");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                            resultMap.putString("error", "BIOMETRIC_ERROR_NONE_ENROLLED");
                            break;
                        case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                            resultMap.putString("error", "BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED");
                            break; 
                    }

                    promise.resolve(resultMap);
                }
            } else {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("available", false);
                resultMap.putString("error", "Unsupported android version");
                promise.resolve(resultMap);
            }
        } catch (Exception e) {
            promise.reject("Error detecting biometrics availability: " + e.getMessage(), "Error detecting biometrics availability: " + e.getMessage());
        }
    }

    @ReactMethod
    public void createKeys(final ReadableMap params, Promise promise) {
        try {
            if (isCurrentSDKMarshmallowOrLater()) {
                deleteBiometricKey();
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, 
                    "AndroidKeyStore"
                );

                int[] preferredKeySizes = {4096, 3072, 2048}; // try bigger first
                KeyPair keyPair = null;
                int chosenSize = -1;

                for (int size : preferredKeySizes) {
                    try {
                        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                                    biometricKeyAlias,
                                    KeyProperties.PURPOSE_SIGN
                                )
                                .setDigests(KeyProperties.DIGEST_SHA256)
                                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(size, RSAKeyGenParameterSpec.F4))
                                .setUserAuthenticationRequired(true)
                                .build();

                        keyPairGenerator.initialize(keyGenParameterSpec);
                        keyPair = keyPairGenerator.generateKeyPair();
                        chosenSize = size;
                        break; // success, stop trying smaller sizes
                    } catch (Exception inner) {
                        // Failed for this size, try next smaller one
                    }
                }

                if (keyPair == null) {
                    promise.reject("KeyGenerationFailed", "Unable to generate RSA key pair with supported size");
                    return;
                }

                PublicKey publicKey = keyPair.getPublic();
                byte[] encodedPublicKey = publicKey.getEncoded();
                String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.NO_WRAP);

                WritableMap resultMap = new WritableNativeMap();
                resultMap.putString("publicKey", publicKeyString);
                resultMap.putInt("keySize", chosenSize);
                promise.resolve(resultMap);

            } else {
                promise.reject("UnsupportedVersion", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("KeyGenError", "Error generating public/private keys: " + e.getMessage());
        }
    }

    private boolean isCurrentSDKMarshmallowOrLater() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;
    }

    @ReactMethod
    public void deleteKeys(Promise promise) {
        if (doesBiometricKeyExist()) {
            boolean deletionSuccessful = deleteBiometricKey();

            if (deletionSuccessful) {
                WritableMap resultMap = new WritableNativeMap();
                resultMap.putBoolean("keysDeleted", true);
                promise.resolve(resultMap);
            } else {
                promise.reject("Error deleting biometric key from keystore", "Error deleting biometric key from keystore");
            }
        } else {
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysDeleted", false);
            promise.resolve(resultMap);
        }
    }

    @ReactMethod
    public void createSignature(final ReadableMap params, final Promise promise) {
        if (isCurrentSDKMarshmallowOrLater()) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String promptMessage = params.getString("promptMessage");
                                String payload = params.getString("payload");
                                String cancelButtonText = params.getString("cancelButtonText");
                                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");

                                String signatureScheme = params.hasKey("signatureScheme") 
                                    ? params.getString("signatureScheme") 
                                    : "PSS"; // default fallback

                                Signature signature;
                                if ("PSS".equalsIgnoreCase(signatureScheme)) {
                                    signature = Signature.getInstance("SHA256withRSA/PSS");
                                    PSSParameterSpec pssSpec = new PSSParameterSpec(
                                            "SHA-256",
                                            "MGF1",
                                            MGF1ParameterSpec.SHA256,
                                            32,
                                            1
                                    );
                                    signature.setParameter(pssSpec);
                                } else {
                                    signature = Signature.getInstance("SHA256withRSA"); // PKCS#1 v1.5
                                }
                                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                                keyStore.load(null);

                                PrivateKey privateKey = (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
                                signature.initSign(privateKey);

                                BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

                                AuthenticationCallback authCallback = new CreateSignatureCallback(promise, payload);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                                biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials), cryptoObject);
                            } catch (Exception e) {
                                promise.reject("Error signing payload: " + e.getMessage(), "Error generating signature: " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
        }
    }

    private PromptInfo getPromptInfo(String promptMessage, String cancelButtonText, boolean allowDeviceCredentials) {
        PromptInfo.Builder builder = new PromptInfo.Builder().setTitle(promptMessage);

        builder.setAllowedAuthenticators(getAllowedAuthenticators(allowDeviceCredentials));

        if (allowDeviceCredentials == false || isCurrentSDK29OrEarlier()) {
            builder.setNegativeButtonText(cancelButtonText);
        }

        return builder.build();
    }

    private int getAllowedAuthenticators(boolean allowDeviceCredentials) {
        if (allowDeviceCredentials && !isCurrentSDK29OrEarlier()) {
            return BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        }
        return BiometricManager.Authenticators.BIOMETRIC_STRONG;
    }

    private boolean isCurrentSDK29OrEarlier() {
        return Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q;
    }

    @ReactMethod
    public void simplePrompt(final ReadableMap params, final Promise promise) {
        if (isCurrentSDKMarshmallowOrLater()) {
            UiThreadUtil.runOnUiThread(
                    new Runnable() {
                        @Override
                        public void run() {
                            try {
                                String promptMessage = params.getString("promptMessage");
                                String cancelButtonText = params.getString("cancelButtonText");
                                boolean allowDeviceCredentials = params.getBoolean("allowDeviceCredentials");

                                AuthenticationCallback authCallback = new SimplePromptCallback(promise);
                                FragmentActivity fragmentActivity = (FragmentActivity) getCurrentActivity();
                                Executor executor = Executors.newSingleThreadExecutor();
                                BiometricPrompt biometricPrompt = new BiometricPrompt(fragmentActivity, executor, authCallback);

                                biometricPrompt.authenticate(getPromptInfo(promptMessage, cancelButtonText, allowDeviceCredentials));
                            } catch (Exception e) {
                                promise.reject("Error displaying local biometric prompt: " + e.getMessage(), "Error displaying local biometric prompt: " + e.getMessage());
                            }
                        }
                    });
        } else {
            promise.reject("Cannot display biometric prompt on android versions below 6.0", "Cannot display biometric prompt on android versions below 6.0");
        }
    }

    @ReactMethod
    public void biometricKeysExist(Promise promise) {
        try {
            boolean doesBiometricKeyExist = doesBiometricKeyExist();
            WritableMap resultMap = new WritableNativeMap();
            resultMap.putBoolean("keysExist", doesBiometricKeyExist);
            promise.resolve(resultMap);
        } catch (Exception e) {
            promise.reject("Error checking if biometric key exists: " + e.getMessage(), "Error checking if biometric key exists: " + e.getMessage());
        }
    }

    protected boolean doesBiometricKeyExist() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            return keyStore.containsAlias(biometricKeyAlias);
        } catch (Exception e) {
            return false;
        }
    }

    protected boolean deleteBiometricKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry(biometricKeyAlias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
