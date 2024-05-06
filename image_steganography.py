from datetime import time
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import cv2
from pywt import dwt2, idwt2, dwt, idwt, Wavelet
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto
from PIL import Image, ImageDraw, ImageFont
import numpy as np
from stegano import lsb
import matplotlib.pyplot as plt
from skimage.metrics import peak_signal_noise_ratio as psnr
from skimage.metrics import structural_similarity as ssim
from skimage.metrics import mean_squared_error as mse


modified_coeffs = None
resolved_coeffs = None


nonce = get_random_bytes(16)

def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def string_to_binary(s):
    return ' '.join(format(ord(c), 'b') for c in s)

class BaseClass:
    def __init__(self, image_path, secret_message) -> None:
        self.image_path = image_path
        self.secret_message = secret_message

    def aes_encrypt(self):
        
        cipher = AES.new(nonce, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(self.secret_message.encode('utf-8'))
        return nonce + tag + ciphertext


    def aes_decrypt(self, data):
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        # print(f"NONCE: {nonce}")
        cipher = AES.new(nonce, AES.MODE_EAX, nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except (ValueError):
            return "Decryption Error: Invalid key or corrupted data"

    def calculate_metrics(original_path, stego_path, computation_time):
        original_image = cv2.imread(original_path)
        stego_image = cv2.imread(stego_path)

        storage_overhead = os.path.getsize(stego_path) - os.path.getsize(original_path)
        # start_time = time.time()
        psnr_value = psnr(original_image, stego_image)
        ssim_value = ssim(original_image, stego_image, multichannel=True)
        mse_value = mse(original_image, stego_image)

        return storage_overhead, computation_time, psnr_value, ssim_value, mse_value
    
    def embed_message_in_ll(self, ll_subband, message):
        # Flatten the LL subband into a 1D array
        ll_flat = ll_subband.flatten()
        length_of_message_in_bin = ''.join(string_to_binary(str(len(message))).split())
        print(f"length of message in binary: {length_of_message_in_bin}")

        # Check if the message can fit into the LL subband
        if len(message+length_of_message_in_bin)  > len(ll_flat):
            raise ValueError("Message is too long to fit into the LL subband")
        
        # Embed the length of the message into the LL subband
        for i in range(18):
            # Convert the current LL coefficient to binary
            coeff_bin = format(int(ll_flat[i]), '08b')

            # Replace the LSB of the coefficient with the current message bit
            new_coeff_bin = coeff_bin[:-1] + length_of_message_in_bin[i]

            # Convert the new coefficient back to an integer
            new_coeff = int(new_coeff_bin, 2)

            # Replace the original coefficient with the new one
            ll_flat[i] = new_coeff


        # Embed the message into the LSB of the LL subband
        for i in range(len(message)):
            # Convert the current LL coefficient to binary
            coeff_bin = format(int(ll_flat[i+18]), '08b')

            # Replace the LSB of the coefficient with the current message bit
            new_coeff_bin = coeff_bin[:-1] + message[i]

            # print(f"COEFF: {coeff_bin}, NEW COEFF: {new_coeff_bin}, BIT: {message[i]}")

            # Convert the new coefficient back to an integer
            new_coeff = int(new_coeff_bin, 2)

            # Replace the original coefficient with the new one
            ll_flat[i+18] = new_coeff

        # Reshape the flat LL subband back into its original 2D shape
        new_ll_subband = ll_flat.reshape(ll_subband.shape)
        return new_ll_subband
    
    def extract_message_from_ll(self, ll_coeffs):
        # Flatten the LL subband into a 1D array
        ll_flat = ll_coeffs.flatten()
        print(f"LL FLAT: {ll_flat}")
        length_of_message = ''
        for i in range(18):
            # Extract the LSB from the current LL coefficient
            length_of_message += str(int(ll_flat[i]) & 1)

        print(f"LENGTH OF MESSAGE: {length_of_message}")



        # Initialize an empty string to hold the extracted bits
        extracted_bits = ''

        # Extract the LSB from each coefficient in the LL subband
        for coeff in ll_flat:
            # Convert the coefficient to binary
            coeff_bin = format(coeff, '08b')

            # Extract the LSB and append it to the extracted bits
            extracted_bits += coeff_bin[-1]

        return extracted_bits

    
    def reconstruct_image(self, coeffs, wavelet):
        return idwt2(np.array(coeffs, dtype=np.float64), wavelet=wavelet)   

    
class WaveletBasedAes(BaseClass):
    def __init__(self, image_path, secret_message) -> None:
        super().__init__(image_path, secret_message)

    def image_steganography(self):
        gray_image = cv2.imread(self.image_path, 0)
        # encrypted_text = self.aes_encrypt()
        message_bits = ' '.join(bin(ord(b))[2:] for b in self.secret_message)
        wavelet = 'haar'  
        coeffs = dwt2(gray_image,wavelet)
        ll_coeffs = coeffs[0]
        embedded_coeffs = self.embed_message_in_ll(ll_coeffs.copy(), ''.join(message_bits.split()))
        new_coeffs = (embedded_coeffs, coeffs[1])

        # Reconstruct stego-image
        stego_image = self.reconstruct_image(new_coeffs, wavelet)

        return stego_image

    def decrypt_and_extract(self,stego_image_path):
        # Load stego-image
        try:
            stego_image = cv2.imread(stego_image_path, 0)
        except FileNotFoundError:
            print("Error: Image file not found")
            return None

        # Perform DWT
        wavelet = 'haar'  
        coeffs = dwt2(stego_image, wavelet)

        # Extract embedded bits from LL sub-band
        ll_coeffs = coeffs[0]
        extracted_bits = self.extract_message_from_ll(ll_coeffs)


        # Decrypt extracted bits with AES
        message = self.aes_decrypt(bitstring_to_bytes( extracted_bits))

        return message




def embed_qr_message(image, message):
    encrypted_message = aes_encrypt(message, nonce)
    qr_code = Image.new('L', (250, 250), color='white')  # Adjust size
    draw = ImageDraw.Draw(qr_code)
    fnt = ImageFont.truetype("arial.ttf", 16)  # Adjust font size
    draw.text((0, 0), encrypted_message, font=fnt, fill='black')

    if image.mode == 'RGB':
        image.convert('L')
    qr_code_width, qr_code_height = qr_code.size

    # (Placeholder) Implement robust QR code embedding logic here
    # ... (consider embedding strategy, capacity optimization)

    return stego_image  # Placeholder, modify image with QR code


def extract_qr_message(stego_image):
    # (Placeholder) Implement robust QR code extraction logic here
    # ... (consider QR code detection, decoding)

    extracted_message = aes_decrypt(extracted_bits, nonce)  # Placeholder
    return extracted_message


def embed_det_message(image, message):
    # Replace with Discrete Cosine Transform (DCT) implementation
    raise NotImplementedError("DCT implementation required for DET steganography")


def extract_det_message(stego_image):
    # Replace with Discrete Cosine Transform (DCT) implementation
    raise NotImplementedError("DCT implementation required for DET steganography")


if __name__ == '__main__':


    ini = WaveletBasedAes("test_image.png", 'Hi, my name is Bhadraksh')
    image = ini.image_steganography()
    cv2.imwrite('haha.jpeg', image)
    decoded_text = ini.decrypt_and_extract('haha.jpeg')

    
    # print(f"DECODED TEXT: {decoded_text}")