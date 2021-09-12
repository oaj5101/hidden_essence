from tkinter import *
from PIL import ImageTk,Image #pip instal pillow
import sqlite3
import tkinter as tk
from tkinter.constants import N
import bcrypt
from tkinter.font import Font #help to import font family
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
import os
from cryptography import fernet
from cryptography.fernet import Fernet
import shutil
from os import stat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


root=Tk()
#size of app
root.geometry("1300x650+0+0")
root.minsize(1300,650)
root.maxsize(1300,650)
#title of app
root.title("Safezone! (easy to handle safe to use)")
#icon if app
root.iconbitmap("images\imgb.png")



#start page of app
def tab1():
	global new_bg
	# for background image
	bg=Image.open("images\Home Page.png")
	resized1=bg.resize((1300,650),Image.ANTIALIAS)
	new_bg=ImageTk.PhotoImage(resized1)
	bg_label=Label(root,image=new_bg)
	bg_label.place(x=0,y=0,relwidth=1,relheight=1)


	def encrypt(p_text, iv, key):
		backend = default_backend()

		cipher = Cipher(algorithms.AES(key),modes.CFB(iv),backend=backend)
		padder = padding.PKCS7(128).padder() # 128 bit
		text = padder.update(p_text) + padder.finalize()
		encryptor = cipher.encryptor()
		c_text = encryptor.update(text) + encryptor.finalize()
		return c_text

	def decrypt(p_text, iv, key):
		backend = default_backend()

		cipher = Cipher(algorithms.AES(key),modes.CFB(iv),backend=backend)
		padder = padding.PKCS7(128).padder() # 128 bit
		text = padder.update(p_text) + padder.finalize()
		decryptor = cipher.decryptor()
		c_text = decryptor.update(p_text) + decryptor.finalize()
		print(c_text)
		return c_text




	# creating frame 1
	def sign_up():


		#creating function of back button
		def back():
			frame1.destroy()
			tab1()


		#creaating function to store userdata
		def userdata(username, password, email, contact, passcode):
			inputuser = username
			username = username+".db"
			
   
			
			print(password)
   
			conn = sqlite3.connect(username)
			c = conn.cursor()
			c.execute("CREATE TABLE IF NOT EXISTS userinfo(username VARCHAR PRIMARY KEY, password VARCHAR NOT NULL, email VARCHAR PRIMARYKEY, contact VHARCHAR PRIMARYKEY)")
			c.execute("INSERT INTO userinfo(username, password, email, contact) VALUES(?,?,?,?)",(inputuser,password,email,contact))
			c.execute("CREATE TABLE IF NOT EXISTS notes(name TEXT PRIMARY KEY, content BLOB)")
			c.execute("CREATE TABLE IF NOT EXISTS files(name VARCHAR PRIMARYKEY,path VARCHAR PRIMARYKEY, file BLOB, filekey BLOB)")
			c.execute("CREATE TABLE IF NOT EXISTS passwords(domain TEXT PRIMARY KEY, username TEXT, password BLOB)")
			conn.commit()
			conn.close()


			

			back()


		def database(username, password, email, contact, passcode):
			
			conn = sqlite3.connect('database.db')
			c= conn.cursor()
			c.execute("INSERT INTO userdata(username, password, email, contact) VALUES(?,?,?,?)",(username,password,email,contact))
			conn.commit()
			conn.close()
			#calling a function that will create a folder for users data to be stored.
			userdata(username, password, email, contact, passcode)


		#checking if contact no is valid
		def verifycontact(username, password, email, contact, passcode):
			contact = str(contact)
			a = len(contact)
			if a == 10 :
			#calling a function to save credentials in the database
				database(username, password, email, contact, passcode)
			else:
				messagebox.showerror("WARNING","contact number should be 10 characters long")


  		#checking if email id is valid
		def verifyemail(username, password, email, contact, passcode):
			email = str(email)
			a = email.find('@')
			print(a)
			if a >= None :
				#calling a function to verify contact number
				verifycontact(username, password, email, contact, passcode)
			else:
				messagebox.showerror("WARNING","Invalid Email address, please try again")
			

  		#encrypting password
		def hashed(username, password, email, contact, passcode):
			
			password = bcrypt.hashpw(password,bcrypt.gensalt())
			#calling a function to  verify email
			verifyemail(username, password, email, contact,passcode)


		#checking if username already exists
		def verifyusername(username, password, email, contact,passcode):
			conn = sqlite3.connect('database.db')
			c = conn.cursor()
			c.execute("SELECT 1 FROM userdata WHERE username=?", (username,))
			if len(c.fetchall()) > 0:
				messagebox.showerror("WARNING","Username already exists, please try again")
			#calling a function to hash the password
			hashed(username, password, email, contact,passcode)



		#getting data from the form on the interface
		def getdata():
			username = text_name.get()			
			password = text_password.get()
			passcode = password
			password = password.encode()
			email = text_email.get()
			contact = text_contact.get()
			#calling a function to verify if the username exists
			verifyusername(username, password, email, contact,passcode)


		#creating database to save users credentials
		def creating_database():
			conn = sqlite3.connect('database.db')
			c = conn.cursor()
			c.execute("CREATE TABLE IF NOT EXISTS userdata(username VARCHAR PRIMARY KEY, password VARCHAR NOT NULL, email VARCHAR PRIMARYKEY, contact VHARCHAR PRIMARYKEY)")
			conn.commit()
			conn.close()
			getdata()

		frame.destroy()
		#large font of login page
		global my_font
		my_font=Font(family="Helvetica",size=25,slant="italic",weight="bold",underline=1)

		frame1=Frame(root,padx=5,pady=60,borderwidth=10,bg="#ACC8E5")
		frame1.pack(padx=70,pady=80)

		lb4=Label(frame1,text="SIGNUP",fg="#112A46",bg="#ACC8E5",font=my_font)
		lb4.grid(row=0,column=0,columnspan=2)

		un_label=Label(frame1,text="Username",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
		un_label.grid(row=1,column=0)

		pa_label=Label(frame1,text="Password",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
		pa_label.grid(row=2,column=0)

		ea_label=Label(frame1,text="Email",fg="#112A46",bg="#ACC8E5",font="	Helvetica 20")
		ea_label.grid(row=3,column=0)

		cn_label=Label(frame1,text="Contact no.",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
		cn_label.grid(row=4,column=0)

		text_name=StringVar()
		name_e1=Entry(frame1,width=60,textvariable=text_name,borderwidth=2)
		#name_e1.config(font="Helvetica 10")
		name_e1.grid(row=1,column=1,pady=5)

		text_password=StringVar()
		pass_e1=Entry(frame1,width=60,textvariable=text_password,borderwidth=2)
		pass_e1.grid(row=2,column=1,pady=5)

		text_email=StringVar()
		email_e1=Entry(frame1,width=60,textvariable=text_email,borderwidth=2)
		email_e1.grid(row=3,column=1,padx=10,pady=5)

		text_contact=StringVar()
		con_e1=Entry(frame1,width=60,textvariable=text_contact,borderwidth=2)
		con_e1.grid(row=4,column=1,padx=10,pady=5)

		button3=Button(frame1,text="Signup",padx=8,pady=8,width=6,command=creating_database ,fg="white",bg="#112A46",borderwidth=0,activebackground="black",font="Helvetica 18")
		button3.bind("<Button-1>")
		button3.place(x=360,y=240) #190

		button4=Button(frame1,text="Back",padx=8,pady=8,width=6,command=back ,fg="white",bg="#112A46",borderwidth=0,activebackground="black",font="Helvetica 18")
		button4.place(x=60,y=240)

		ck=Checkbutton(frame1,text="please check the filled information", font="Helvetica 13 bold",fg="#112A46",bg="#ACC8E5",activebackground="#ACC8E5")
		ck.grid(row=5,column=1,columnspan=2,padx=5,pady=5)

	#creating frame 2
	def login():
		def main(username, passcode):
			print('mohit is great')
			root.destroy()
			root3=Tk()
			root3.title("Safezone")
			root3.iconbitmap("images\imgb.png")
			root3.geometry("1300x650+0+0")
			root3.minsize(1300,650)
			root3.maxsize(1300,650)
			root3.overrideredirect(1)

			#..background imagae for frame2
			bg2=Image.open("images\Home Page.png")
			#resize
			resized3=bg2.resize((1300,650),Image.ANTIALIAS)
			new_bg2=ImageTk.PhotoImage(resized3)
			bg_label2=Label(root3,image=new_bg2)
			bg_label2.place(x=0,y=0,relwidth=1,relheight=1)


			notebook=ttk.Notebook(root3)
			page1=Frame(notebook,bg="#ACC8E5") #tearoff=False
			page2=Frame(notebook,bg="#ACC8E5")
			page3=Frame(notebook,bg="#ACC8E5")


			notebook.add(page1,text="Notepad")
			notebook.add(page2,text="File Encryption")
			notebook.add(page3,text="password")
			notebook.pack(expand=True,fill="both")#expand is use so that when we will increase or decress it will be in same place and size


			databasename = username+".db"
			os.mkdir('displayfolder')
			

			conn = sqlite3.connect(databasename)
			c = conn.cursor()
			#========================================================================================================================================
			#====================================================== NOTEPAD =========================================================================
			#========================================================================================================================================

			def logout_note():

				shutil.rmtree('displayfolder')

				
				root3.destroy()

			def listbox_show2(title):
				# this function displays the domain names in the list for which ".insert" .
				listbox2.insert("end",title)
				#".delete" is used to erase the data types in the entry labels.
				#name_e2.delete(0,END)
				#pass_e2.delete(0,END)
				#text_e2.delete(0,END)




			def save_file():
				#fetching data from input box.
				note=str(entry.get(1.0,END))
				note = note+'...///stringwillbeslicedhere'	

				title=str(entrytitle.get())

				#checking if title already exists.
				c.execute("SELECT 1 FROM notes WHERE name=?",(title,))
				a = c.fetchall()
				a =len(a)
				print(a)
				if a>0:
					#creating a warning message if the title already exists and asking if user woould like to update the previous entry.
					if messagebox.askyesno('Alert', 'This file name exist already do you want to update',icon='info')==True:

						#encrypting the info if user presses yes on the warning dialog box
						note = bytes(note,'utf-8')
						iv = b'TestMeInitVector'
						
						key = str(passcode)
						l = len(key)
						if l>16:
							while l>16:
								key = key.rstrip(key[-1])
								print(key)
								l = l-1
								
						elif l<16:
							while l<16:
								
								key = key+'.'
								l = l+1

						else:
							return key
			
						note = encrypt(note, iv, key)
      
      
						#updating the database with the new information.
						c.execute("UPDATE NOTES SET content=? WHERE name=?",(note,title))
						
						conn.commit()
						#entrytitle.delete(1.0,END)
						#entry.delete(1.0,END)
				else:
					#encrypting information.
					key = str(passcode)
					l = len(key)
					if l>16:
						while l>16:
							key = key.rstrip(key[-1])
							print(key)
							l = l-1
							
					elif l<16:
						while l<16:
							
							key = key+'.'
							l = l+1

					else:
						return key

					key = bytes(key,'utf-8')
					iv = b'TestMeInitVector'
					note = bytes(note,'utf-8')
					note = encrypt(note, iv, key)
			
					#saving info on the database
					c.execute("INSERT INTO notes (name, content) VALUES (?,?)", (title, note))
					conn.commit()

					#displaying the title of the newly saved note on the list.
					listbox_show2(title)
					#entrytitle.delete(0,END)
					#entry.delete(0,END)



			def decrypt_note():
				#this function will display the username and password of selected domain from the list
				a = listbox2.get(ANCHOR)

				#fetching data of selected domain from database
				c.execute("SELECT name, content FROM notes WHERE name =?",(a,))
				data = c.fetchall()
    
				for i in data:
					data = i
					t , n = data

				#decrypting the content.
					key = str(passcode)
					l = len(key)
					if l>16:
						while l>16:
							key = key.rstrip(key[-1])
							print(key)
							l = l-1
							
					elif l<16:
						while l<16:
							
							key = key+'.'
							l = l+1

					else:
						return key
					iv = b'TestMeInitVector'
					key = bytes(key,'utf-8')
					n = decrypt(n, iv, key)

					n = str(n,'utf-8')
					x = n.find('...///stringwillbeslicedhere')
					print(x)
					n = n[:x]
					


				#displaying the decrypted data in the textareas.
				entrytitle.delete(0,END)
				entrytitle.insert(INSERT,t)

				entry.delete(1.0,END)
				entry.insert(INSERT,n)

			def delete_note():
				#this function deletes the selected data from database.
				#"listbox.get()" is used for geting selected title name into a variable.
				a = listbox2.get(ANCHOR)

				# delete from display.
				listbox2.delete(ANCHOR)

				#delete from database.
				c.execute("DELETE FROM notes WHERE name=?",(a,))
				conn.commit()

				#if the content of the deleted files were on display they will be deleted
				if str(entrytitle.get())==a:
					entrytitle.delete(0,END)
					entry.delete(1.0,END)





			#scollbar
			scroll_y=Scrollbar(page1)
			scroll_y.pack(side=RIGHT,fill=Y,pady=(80,11),padx=(0,10))


			veiw3=Button(page1,text="View",width=10,bg="#112A46",fg="white",borderwidth=0,command=decrypt_note,font="Helvetica 10")
			veiw3.place(x=10,y=500)

			delete3=Button(page1,text="Delete",width=10,bg="#112A46",fg="white",borderwidth=0,command=delete_note,font="Helvetica 10")
			delete3.place(x=160,y=500)


			save=Button(page1,text="Save",width=15,bg="#112A46",fg="white",borderwidth=0,command=save_file,font="Helvetica 16")
			save.place(x=500,y=20)

			logoutnote=Button(page1,text="Logout",width=10,bg="#112A46",fg="white",borderwidth=0,command=logout_note,font="Helvetica 16")
			logoutnote.place(x=1125,y=15)

			entrytitle=Entry(page1,width=87)
			entrytitle.config(font="Helvetica 15")
			entrytitle.place(x=270,y=130)


			entry=Text(page1,height=18,width=87,wrap=WORD,yscrollcommand=scroll_y.set)
			entry.config(font="Helvetica 15")
			entry.place(x=270,y=200)

			scroll_y.config(command=entry.yview)

			title_label=Label(page1,text="Title:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			title_label.place(x=300,y=85)

			note_label=Label(page1,text="Note:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			note_label.place(x=300,y=160)

			listbox2=Listbox(page1,height=25,width=40)
			listbox2.place(x=10,y=80)
			scroll1=Scrollbar(page1,command=listbox2.yview)
			listbox2.config(yscrollcommand=scroll1.set)
			scroll1.pack(side=RIGHT,fill=Y,pady=(80,150),padx=(0,995))

			#taking data from passwords table to display on the list
			c.execute("SELECT name, content FROM notes")
			data = c.fetchall()
			for i in data:
				data = i
				title, note= data
				listbox_show2(title)
			#=======================================================================================================================================
			#===================================================PASSWORDS FUNCTION==================================================================
			#=======================================================================================================================================
			def logout_pass():

				shutil.rmtree('displayfolder')

				
				root3.destroy()



			def savepass():

				#this function encrypts and saves entered data into the database

				#converting user inputs into variables.
				domain_name = text_name.get()
				userid  = user_name.get()
				password = text_password.get()
				password = password+'...///stringwillbeslicedhere'
				#checking if the domain already exists
				c.execute("SELECT 1 FROM passwords WHERE domain=?",(domain_name,))
				a = c.fetchall()
				a =len(a)
				print(a)
				if a>0:
					#error message if domain name already exists
					if messagebox.askyesno('Alert', 'This file name exist already do you want to update',icon='info')==True:
						#genereting encryption key

						key = str(passcode)
						l = len(key)
						if l>16:
							while l>16:
								key = key.rstrip(key[-1])
								print(key)
								l = l-1
								
						elif l<16:
							while l<16:
								
								key = key+'.'
								l = l+1

						else:
							return key
						iv = b'TestMeInitVector'
						password = password.encode()
						password = encrypt(password, iv, key)


						#updating the database
						c.execute("UPDATE passwords SET username=? WHERE domain=?",(userid,domain_name))

						c.execute("UPDATE passwords SET password=? WHERE domain=?",(password,domain_name))
						

						conn.commit()

				else:
        			#genereting encryption key

					key = str(passcode)
					l = len(key)
					if l>16:
						while l>16:
							key = key.rstrip(key[-1])
							print(key)
							l = l-1
							
					elif l<16:
						while l<16:
							
							key = key+'.'
							l = l+1

					else:
						return key
  
  
					key = key.encode()
					iv = b'TestMeInitVector'
					password = password.encode()
					password = encrypt(password, iv, key)


					#updating the database
					c.execute("INSERT INTO passwords (domain, username, password) VALUES (?,?,?)", (domain_name, userid, password))
					conn.commit()
					#displaying newly saved domain on list.
					listbox_show(domain_name)

			def listbox_show(domain_name):
				# this function displays the domain names in the list for which ".insert" .
				listbox.insert("end",domain_name)
				#".delete" is used to erase the data types in the entry labels.
				name_e2.delete(0,END)
				pass_e2.delete(0,END)
				text_e2.delete(0,END)


			def delete():
				#this function deletes the selected data from database.
				#"listbox.get()" is used for geting selected domain name into a variable.
				a = listbox.get(ANCHOR)
				listbox.delete(ANCHOR)   # delete from display.
				c.execute("DELETE FROM passwords WHERE domain=?",(a,))  #delete from database.
				conn.commit()

				#clearing the output displays.
				show2.config(text= " ")
				show4.config(text= " ")


			def view_file():
				#this function will display the username and password of selected domain from the list
				a = listbox.get(ANCHOR)
				#fetching data of selected domain from database
				c.execute("SELECT domain, username, password FROM passwords WHERE domain =?",(a,))
				data = c.fetchall()
				for i in data:
					data = i
					domain_name, username , password = data

				#decrypting password
				key = str(passcode)
				l = len(key)
				if l>16:
					while l>16:
						key = key.rstrip(key[-1])
						print(key)
						l = l-1
						
				elif l<16:
					while l<16:
						
						key = key+'.'
						l = l+1

				else:
					return key
				key = key.encode()
				iv = b'TestMeInitVector'
				password = decrypt(password, iv, key)

				password = str(password,'utf-8')
				x = password.find('...')
				print(x)
				password = password[:x]
				


				# displaying username and password on the interface.
				show2.config(text= username)
				show4.config(text= password)

			# adding a scrollbar to the list
			scroll_y1=Scrollbar(page3)
			scroll_y1.pack(side=RIGHT,fill=Y)
			# submit button which will call savepass function
			submit=Button(page3,text="submit",width=15,bg="#112A46",fg="white",borderwidth=0,command=savepass,font="Helvetica 18")
			submit.place(x=250,y=300)
			# Delete button which will call delete function
			delete1=Button(page3,text="delete",width=15,bg="#112A46",fg="white",borderwidth=0,command=delete,font="Helvetica 18")
			delete1.place(x=650,y=525)
			#view button which will call view file function
			view=Button(page3,text="view",width=15,bg="#112A46",fg="white",borderwidth=0,command=view_file,font="Helvetica 18")
			view.place(x=1000,y=525)
   
			logoutpass=Button(page3,text="Logout",width=10,bg="#112A46",fg="white",borderwidth=0,command=logout_pass,font="Helvetica 16")
			logoutpass.place(x=1125,y=15)
   

			#input labels
			te_labe2=Label(page3,text="social identity",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			te_labe2.place(x=50,y=10)

			un_labe2=Label(page3,text="Username:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			un_labe2.place(x=50,y=100)

			pa_labe2=Label(page3,text="Password:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			pa_labe2.place(x=50,y=200)

			#input text areas
			text_name=StringVar()
			text_e2=Entry(page3,width=50,textvariable=text_name,borderwidth=2)
			text_e2.config(font="Helvetica 15")
			text_e2.place(x=50,y=60)

			user_name=StringVar()
			name_e2=Entry(page3,width=50,textvariable=user_name,borderwidth=2)
			name_e2.config(font="Helvetica 15")
			name_e2.place(x=50,y=150)

			text_password=StringVar()
			pass_e2=Entry(page3,width=50,textvariable=text_password,borderwidth=2)
			pass_e2.config(font="Helvetica 15")
			pass_e2.place(x=50,y=250)

			#createing a listbox
			listbox=Listbox(page3,height=19,width=100,yscrollcommand=scroll_y1.set)
			#entry1.config(font="Helvetica 15")
			listbox.place(x=630,y=150)
			scroll_y1.config(command=listbox.yview)

			#creating output display labels

			show1=Label(page3,text="Username :",fg="#112A46",bg="#ACC8E5",font="Helvetica 18")
			show1.place(x=100,y=500)

			show2=Label(page3,text="",fg="#112A46",bg="#ACC8E5",font="Helvetica 18")
			show2.place(x=230,y=500)

			show3=Label(page3,text="Password :",fg="#112A46",bg="#ACC8E5",font="Helvetica 18")
			show3.place(x=100,y=560)

			show4=Label(page3,text="",fg="#112A46",bg="#ACC8E5",font="Helvetica 18")
			show4.place(x=230,y=560)


			show5=Label(page3,text='output',fg="#112A46",bg="#ACC8E5",font="Helvetica 30")
			show5.place(x=50,y=400)

			#taking data from passwords table to display on the list
			c.execute("SELECT domain, username FROM passwords")
			rows = c.fetchall()
			for i in rows:
				rows = i
				domain_name, username= rows
				#displaying every entry on database in the list
				listbox_show(domain_name)

			#============================================================================================================================
			#=============================================== FILE ENCRYPTION ============================================================
			#============================================================================================================================

			def logout_file():

				shutil.rmtree('displayfolder')

				
				root3.destroy()
				
			def view_file2():
				#this function will display the username and password of selected domain from the list
				
				#this command will get the filename selected by the user.
				a = listbox1.get(ANCHOR)
				print(a)
				#fetching all data from the row of selectd filename.
				c.execute("SELECT name, path, file , filekey FROM files WHERE name =?",(a,))
				data = c.fetchone()

				print(data)
				name , path, file_data, filekey = data




				key = str(passcode)

				l = len(key)
				if l>16:
					while l>16:
						key = key.rstrip(key[-1])
						print(key)
						l = l-1
						
				elif l<16:
					while l<16:
						
						key = key+'.'
						l = l+1

				else:
					return key

				key = key.encode()				
				iv = b'TestMeInitVector'
				enckey = decrypt(filekey, iv, key)
    
    
				enckey = enckey.decode()
				print(enckey)

				enckey = enckey[:44]
				print(key)

				enckey = enckey.encode()
				print(key)
    
    
				f = Fernet(enckey)
				file_data = f.decrypt(file_data)
    

				filepath = os.path.join('displayfolder', name)
				#filepath = 'displayfolder/'+name

				with open(filepath, "wb") as file:
					file.write(file_data)                                              #saved the decrpted data in the same file at same path
					print("Decrypted")


				
				#displaying the file.
				os.system(filepath)

				


			def delete_file():

   				#this function deletes the selected data from database.
				#"listbox.get()" is used for geting selected domain name into a variable.
				a = listbox1.get(ANCHOR)
				listbox1.delete(ANCHOR)   # delete from display.
				c.execute("DELETE FROM files WHERE name=?",(a,))  #delete from database.
				conn.commit()


			def listbox_show3(file_name):
				#this will display the name of encrypted file on a list.
				listbox1.insert("end",file_name)


			def encryptfile():
       
				enckey = Fernet.generate_key()
				f = Fernet(enckey)
				
				#creating selectfile dialog box for the user
				filepath = filedialog.askopenfilename(title="Choose a file")

				filepath = str(filepath)

				#getting filename from the path.
				file_name = os.path.basename(filepath)

				#reading data of the file into file_data variable.
				with open(filepath , "rb") as file:
					file_data = file.read()                                                         #load the keys
				#encoded_msg = file_data.encode('utf-8')                                              #encode the encrypt_message
				                                                             
				encrypted_msg = f.encrypt(file_data)
				with open(filepath, "wb") as file:                                     #encrypted the message
					file.write(encrypted_msg)
				#print("Encrypted")
    
				if messagebox.askyesno('Alert', 'File is ENCRYPTED AND STORED IN DATABASE,would you like to delete the encrypted file from its original location to save storage capacity',icon='info')==True:
					os.remove(filepath)

				#encrypting data in file_data variable.
				key = str(passcode)



				l = len(key)
				if l>16:
					while l>16:
						key = key.rstrip(key[-1])
						print(key)
						l = l-1
						
				elif l<16:
					while l<16:
						
						key = key+'.'
						l = l+1

				else:
					return key

				key = key.encode()				
				iv = b'TestMeInitVector'
				enckey = encrypt(enckey, iv, key)



				#saving key, path and name on database.
				c.execute("INSERT INTO files (name, path, file, filekey) VALUES (?,?,?,?)",(file_name,filepath,encrypted_msg, enckey))
				conn.commit()
				#displaying newly saved file's name on list.
				listbox_show3(file_name)






			big_label1=Label(page2,text="..... File encrytion .....",fg="black",bg="#ACC8E5",font="Helvetica 25 bold")
			big_label1=Label(page2,text="..... File encrytion .....",fg="black",bg="#ACC8E5",font="Helvetica 25 bold")
			big_label1.place(x=150,y=20)

			#ef_label=Label(page2,text="Select the file to encrypt",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			#ef_label.place(x=150,y=120)

			e_label=Label(page2,text="To encrypt file click here",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
			e_label.place(x=150,y=180)




			#Select1=Button(page2,text="Select",width=15,bg="#112A46",fg="white",borderwidth=0,command=select_file,font="Helvetica 16")
			#Select1.place(x=200,y=160)

			encrypt1=Button(page2,text="Encrypt",width=15,bg="#112A46",fg="white",borderwidth=0,command=encryptfile,font="Helvetica 16")
			encrypt1.place(x=200,y=220)

			logout3=Button(page2,text="Logout",width=10,bg="#112A46",fg="white",borderwidth=0,command=logout_file,font="Helvetica 16")
			logout3.place(x=1125,y=15)

			listbox1=Listbox(page2,height=28,width=90)
			#entry1.config(font="Helvetica 15")
			listbox1.place(x=600,y=100)
			#scroll_y1.config(command=listbox.yview)

			scroll=Scrollbar(page2,command=listbox1.yview)
			listbox1.config(yscrollcommand=scroll.set)
			scroll.pack(side=RIGHT,fill=Y)

			delete2=Button(page2,text="delete",width=15,bg="#112A46",fg="white",borderwidth=0,command=delete_file,font="Helvetica 18")
			delete2.place(x=600,y=570)

			view2=Button(page2,text="view",width=15,bg="#112A46",fg="white",borderwidth=0,command=view_file2,font="Helvetica 18")
			view2.place(x=930,y=570)

			#extracting
			c.execute("SELECT name, path FROM files")
			rows = c.fetchall()
			for i in rows:
				rows = i
				file_name, path= rows
				#displaying every entry on database in the list
				listbox_show3(file_name)


			root3.mainloop()

		def checkfolder(username, passcode):
			isdir = os.path.isdir('displayfolder')
			if isdir == True:
				shutil.rmtree('displayfolder')
				main(username, passcode)

			else:
				main(username, passcode)
   
				


		#Verifying if the password is correct
		def verifypassword(data,passcode):
			for i in data:
				data = i
				username, password = data
			print(username)
			print(password)
			if bcrypt.checkpw(passcode, password):

				print("yes you are right")
    

     
				checkfolder(username,passcode)

			else:
				messagebox.showerror("INCORRECT PASSWORD","Please try again")

		#getting input from the interface and userdata from the database
		def login_db():
			user = text_name.get()
			passcode = text_password.get()
			passcode = passcode.encode()
			conn = sqlite3.connect('database.db')
			c = conn.cursor()


			c.execute("SELECT username, password FROM userdata WHERE username =?",(user,))
			data = c.fetchall()
			userlist = len(data)
			if userlist>0:

				#calling a function to verify the password
				verifypassword(data,passcode)
			else:
				messagebox.showerror("INCORRECT USERNAME","username doesn't exist please try again")


		def sign_up1():
			frame2.destroy()
			sign_up()

		global link_font
		link_font=Font(family="Helvetica",size=15,slant="italic",underline=1)

		global my_font1
		my_font1=Font(family="Helvetica",size=25,slant="italic",weight="bold",underline=1)


		frame.destroy()
		#..creating frame
		frame2=Frame(root,padx=10,pady=10,borderwidth=10,bg="#ACC8E5")
		frame2.pack(padx= 100,pady=110)

		lb4=Label(frame2,text="LOGIN",fg="#112A46",bg="#ACC8E5",font=my_font1)
		lb4.grid(row=0,column=0,columnspan=3)


		#creating label and entry for frame2

		un_labe2=Label(frame2,text="Username:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
		un_labe2.grid(row=1,column=1,padx=5)

		pa_labe2=Label(frame2,text="Password:",fg="#112A46",bg="#ACC8E5",font="Helvetica 20")
		pa_labe2.grid(row=2,column=1,padx=5)

		text_name=StringVar()
		name_e2=Entry(frame2,width=60,textvariable=text_name,borderwidth=2)
		name_e2.grid(row=1,column=2,pady=5)

		text_password=StringVar()
		pass_e2=Entry(frame2,width=60,textvariable=text_password,borderwidth=2,show="*")
		pass_e2.grid(row=2,column=2,pady=5)

		button5=Button(frame2,text="Login",padx=8,pady=8,width=6,command=login_db,fg="white",bg="#112A46",borderwidth=0,activebackground="black",font="Helvetica 18")
		button5.bind("<Button-1>")
		button5.grid(row=3,column=1,columnspan=3,padx=10,pady=5)

		button6=Button(frame2,text="If have'nt Signup then click here",command=sign_up1 ,width=30,pady=8,fg="#112A46", bg="#ACC8E5",borderwidth=0,activebackground="#ACC8E5",font=link_font)
		button6.grid(row=4,column=0,columnspan=3,padx=10,pady=5)

		#.. icon image..
		global new_photo1
		global new_photo2

		photo1=Image.open("images\img8.png")
		resized4=photo1.resize((45,45),Image.ANTIALIAS)
		new_photo1=ImageTk.PhotoImage(resized4)
		photo_label1=Label(frame2,image=new_photo1,height=22,width=22)
		photo_label1.grid(row=1,column=0,padx=5,pady=10)

		photo2=Image.open("images\img12.png")
		resized5=photo2.resize((50,52),Image.ANTIALIAS)
		new_photo2=ImageTk.PhotoImage(resized5)
		photo_label2=Label(frame2,image=new_photo2,height=22,width=22)
		photo_label2.grid(row=2,column=0,padx=5,pady=10)




# ===========================================================================================================================================
#====================================================HOME PAGE DESIGN========================================================================
#============================================================================================================================================
	frame=Frame(root,padx=10,pady=5,borderwidth=10,bg="#ACC8E5")
	frame.pack(padx= 100,pady=100) #,pady=150


	global my_font1
	my_font1=Font(family="Helvetica",size=25,slant="italic",weight="bold",underline=1)



	lb4=Label(frame,text="SAFEZONE!",fg="red",bg="#ACC8E5",font=my_font1)
	lb4.grid(row=0,column=0,columnspan=3,pady=10)


	#frame lables and buttons
	lb1=Label(frame,text=" If new user please Signup",fg="#112A46",bg="#ACC8E5",font=("Helvetica",15,"bold"))
	lb1.grid(row=1,column=0,columnspan=3,pady=5)

	button1=Button(frame,text="SIGN-UP" ,command=sign_up,width=10,pady=10,fg="#112A46")
	button1.bind("<Button-1>")  #after clicking button1 def speak will run
	button1.grid(row=2,column=1,padx=10,pady=10)

	lb2=Label(frame,text=" If account exist then please Login",fg="#112A46",bg="#ACC8E5",font=("Helvetica",15,"bold"),padx=10)
	lb2.grid(row=3,column=0,columnspan=3)


	button2=Button(frame,text="LOGIN",width=10,pady=10,fg="#112A46",command=login)
	button2.bind("<Button-1>")
	button2.grid(row=4,column=1,padx=10,pady=15)








tab1()    #calling the function for initiative
root.mainloop()
