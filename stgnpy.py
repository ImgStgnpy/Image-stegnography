from tkinter import *
import tkinter.filedialog
from tkinter import messagebox
from PIL import ImageTk, Image
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import threading
import queue

class PasswordDialog(Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent)
        self.parent = parent
        self.title(title)
        self.result = None

        self.label = Label(self, text="Enter password:")
        self.label.pack(padx=10, pady=10)

        self.entry = Entry(self, show="*")
        self.entry.pack(padx=10, pady=5)

        self.button = Button(self, text="OK", command=self.ok)
        self.button.pack(pady=10)

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.transient(parent)
        self.grab_set()

    def ok(self):
        self.result = self.entry.get()
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

class IMG_Stegno:
    def __init__(self, root):
        self.root = root
        self.salt = os.urandom(16)
        self.password_queue = queue.Queue()

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def main(self):
        self.root.title('Image Steganography with PDF Support')
        self.root.geometry('500x600')
        self.root.resizable(width=False, height=False)
        self.root.config(bg='#f0f0f0')
        frame = Frame(self.root, bg='#f0f0f0')
        frame.grid()

        title = Label(frame, text='Image Steganography', bg='#f0f0f0', fg='#102542')
        title.config(font=('Times New Roman', 30, 'bold'))
        title.grid(pady=20)

        encode = Button(frame, text="Encode PDF", command=lambda: self.encode_frame1(frame), padx=20, bg='#102542', fg='#ffffff')
        encode.config(font=('Helvetica', 16))
        encode.grid(row=2, pady=10)

        decode = Button(frame, text="Decode PDF", command=lambda: self.decode_frame1(frame), padx=20, bg='#102542', fg='#ffffff')
        decode.config(font=('Helvetica', 16))
        decode.grid(row=3, pady=10)

        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def back(self, frame):
        frame.destroy()
        self.main()

    def encode_frame1(self, F):
        F.destroy()
        F2 = Frame(self.root, bg='#f0f0f0')
        label1 = Label(F2, text='Select the Image to hide PDF:', bg='#f0f0f0', fg='#102542')
        label1.config(font=('Times New Roman', 25, 'bold'))
        label1.grid(pady=20)

        button_bws = Button(F2, text='Select', command=lambda: self.encode_frame2(F2), bg='#102542', fg='#ffffff')
        button_bws.config(font=('Helvetica', 18))
        button_bws.grid(pady=10)

        button_back = Button(F2, text='Go Back', command=lambda: self.back(F2), bg='#102542', fg='#ffffff')
        button_back.config(font=('Helvetica', 18))
        button_back.grid(pady=20)

        F2.grid()

    def decode_frame1(self, F):
        F.destroy()
        d_f2 = Frame(self.root, bg='#f0f0f0')
        label1 = Label(d_f2, text='Select Image with Hidden PDF:', bg='#f0f0f0', fg='#102542')
        label1.config(font=('Times New Roman', 25, 'bold'))
        label1.grid(pady=20)

        button_bws = Button(d_f2, text='Select', command=lambda: self.decode_frame2(d_f2), bg='#102542', fg='#ffffff')
        button_bws.config(font=('Helvetica', 18))
        button_bws.grid(pady=10)

        button_back = Button(d_f2, text='Go Back', command=lambda: self.back(d_f2), bg='#102542', fg='#ffffff')
        button_back.config(font=('Helvetica', 18))
        button_back.grid(pady=20)

        d_f2.grid()

    def encode_frame2(self, e_F2):
        myfile = tkinter.filedialog.askopenfilename(filetypes=[('Image Files', '*.png;*.jpg;*.jpeg'), ('All Files', '*.*')])
        if not myfile:
            messagebox.showerror("Error", "No image selected!")
        else:
            pdf_file = tkinter.filedialog.askopenfilename(filetypes=[('PDF Files', '*.pdf')])
            if not pdf_file:
                messagebox.showerror("Error", "No PDF selected!")
            else:
                my_img = Image.open(myfile)
                new_image = my_img.resize((300, 200))
                img = ImageTk.PhotoImage(new_image)

                e_pg = Frame(self.root, bg='#f0f0f0')
                label3 = Label(e_pg, text='Selected Image', bg='#f0f0f0', fg='#102542')
                label3.config(font=('Helvetica', 18, 'bold'))
                label3.grid(pady=10)

                board = Label(e_pg, image=img, bg='#f0f0f0')
                board.image = img
                board.grid(pady=10)

                button_back = Button(e_pg, text='Encode PDF', command=lambda: [self.enc_pdf(my_img, pdf_file), self.back(e_pg)], bg='#102542', fg='#ffffff')
                button_back.config(font=('Helvetica', 16))
                button_back.grid(pady=15)

                button_cancel = Button(e_pg, text='Go Back', command=lambda: self.back(e_pg), bg='#102542', fg='#ffffff')
                button_cancel.config(font=('Helvetica', 16))
                button_cancel.grid(pady=15)

                e_pg.grid(row=1)
                e_F2.destroy()

    def decode_frame2(self, d_F2):
        myfile = tkinter.filedialog.askopenfilename(filetypes=[('Image Files', '*.png;*.jpg;*.jpeg'), ('All Files', '*.*')])
        if not myfile:
            messagebox.showerror("Error", "No image selected!")
        else:
            pdf_output_path = tkinter.filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[('PDF Files', '*.pdf')])
            if pdf_output_path:
                self.get_password("Decryption Password")
                thread = threading.Thread(target=self.dec_pdf, args=(myfile, pdf_output_path))
                thread.start()
            d_F2.destroy()

    def get_password(self, title):
        dialog = PasswordDialog(self.root, title)
        self.root.wait_window(dialog)
        self.password_queue.put(dialog.result)

    def enc_pdf(self, img, file_path):
        print("Encoding PDF...")
        self.get_password("Encryption Password")
        password = self.password_queue.get()

        if not password:
            messagebox.showerror("Error", "Password is required for encryption.")
            return

        key = self.generate_key(password, self.salt)
        cipher_suite = Fernet(key)

        with open(file_path, 'rb') as f:
            binary_file_data = f.read()
        print(f"Read {len(binary_file_data)} bytes from PDF file.")

        encrypted_data = cipher_suite.encrypt(binary_file_data)
        print(f"Encrypted data length: {len(encrypted_data)} bytes.")

        data_to_hide = self.salt + encrypted_data

        binary_data = ''.join(format(byte, '08b') for byte in data_to_hide)
        binary_data += '1111111111111110'  # Add a delimiter at the end
        print(f"Binary data length: {len(binary_data)} bits.")

        max_bits = img.width * img.height * 3
        if len(binary_data) > max_bits:
            raise ValueError("PDF file is too large for the image")

        encoded_img = img.copy()
        data = iter(encoded_img.getdata())

        for i in range(0, len(binary_data), 3):
            try:
                r, g, b = next(data)
                r = (r & ~1) | int(binary_data[i]) if i < len(binary_data) else r
                g = (g & ~1) | int(binary_data[i + 1]) if i + 1 < len(binary_data) else g
                b = (b & ~1) | int(binary_data[i + 2]) if i + 2 < len(binary_data) else b
                encoded_img.putpixel((i // 3 % img.width, i // 3 // img.width), (r, g, b))
            except StopIteration:
                print("Not enough pixels to encode all data.")
                break

        save_path = tkinter.filedialog.asksaveasfilename(defaultextension=".png", filetypes=[('PNG Files', '*.png')])
        if save_path:
            encoded_img.save(save_path)
            print(f"Encoded image saved at: {save_path}")
            messagebox.showinfo("Success", f"Encoded image saved as {save_path}")

    def dec_pdf(self, img_path, output_path):
        print("Decoding PDF...")
        password = self.password_queue.get()

        if not password:
            messagebox.showerror("Error", "Password is required for decryption.")
            return

        img = Image.open(img_path)
        img_data = iter(img.getdata())
        binary_data = bytearray()

        while True:
            try:
                r, g, b = next(img_data)
                binary_data.append(r & 1)
                binary_data.append(g & 1)
                binary_data.append(b & 1)

                if len(binary_data) >= 16 and binary_data[-16:] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    binary_data = binary_data[:-16]
                    break
            except StopIteration:
                print("End of image data reached.")
                break

        decoded_bytes = bytes(int(''.join(map(str, binary_data[i:i+8])), 2) for i in range(0, len(binary_data), 8))
        print(f"Decoded data length: {len(decoded_bytes)} bytes.")

        salt = decoded_bytes[:16]
        encrypted_data = decoded_bytes[16:]

        key = self.generate_key(password, salt)
        cipher_suite = Fernet(key)

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"PDF saved at {output_path}")
            messagebox.showinfo("Success", f"PDF successfully decoded and saved as {output_path}")
        except Exception as e:
            print(f"Decryption failed: {e}")
            messagebox.showerror("Error", "Decryption failed. Incorrect password or corrupted data.")

if __name__ == '__main__':
    root = Tk()
    app = IMG_Stegno(root)
    app.main()
    root.mainloop()
