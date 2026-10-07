import os
import numpy as np
import matplotlib.pyplot as plt

from data import IMAGE
from modes import ecb_encrypt

def main():
    key = os.urandom(16)
    
    # Encrypt the mock image data using ECB mode
    ciphertext = ecb_encrypt(IMAGE, key)
    
    # Exact dimensions based on data.py (72 width x 4 height = 288 bytes)
    width = 72
    height = 4
    
    try:
        # Convert ciphertext bytes into a numpy array of 8-bit unsigned integers
        pixel_data = np.frombuffer(ciphertext, dtype=np.uint8)
        
        # Reshape the 1D array into a 2D matrix representing an image
        image_matrix = pixel_data.reshape((height, width))
        
        # Render the image matrix
        plt.imshow(image_matrix, cmap='gray')
        plt.title("ECB Mode Leak (Visible Structure)")
        plt.axis('off')
        
        # Save the visualization to disk
        plt.savefig("ecb_leak_pattern.png")
        
    except ValueError as e:
        print(f"Dimension error: {e}")

if __name__ == "__main__":
    main()