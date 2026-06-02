import tkinter as tk
from gui import PasswordCheckerApp     


def main() -> None:
   
    root = tk.Tk()

    try:
        root.iconbitmap(default="")   
    except Exception:
        pass   

    try:
        import ctypes
        HWND  = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(2)        
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            HWND,
            20,                     
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
    except Exception:
        pass    

    _app = PasswordCheckerApp(root)

    root.mainloop()



if __name__ == "__main__":
    main()
