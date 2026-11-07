import tkinter as tk
from gui.app import ProxyApp

def main():
    root = tk.Tk()
    ProxyApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()