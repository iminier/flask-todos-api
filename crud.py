from pymongo import MongoClient

client = MongoClient('mongodb://testing:1000Pass@ds111851.mlab.com:11851/crtestdb')
db = client.crtestdb

def main():
	while(1):
		selection = input('\nSelect 1 to Insert, 2 to Update, 3 to Read, 4 to Delete\n')

		if selection == '1':
			insert()
		elif selection == '2':
			update()
		elif selection == '3':
			read()
		elif selection == '4':
			delete()
		else:
			print('\n INVALID SELECTION \n')

def insert():
	try:
		employeeId = input('Enter Employee id :')
		employeeName = input('Enter Name :')
		employeeAge = input('Enter Age :')
		employeeCountry = input('Enter Country :')
	
		db.Employees.insert_one({
			"id" : employeeId,
			"name" : employeeName,
			"age" : employeeAge,
			"country" : employeeCountry
		})
		
		print('Inserted data successfully')

	except Exception as e:
		print(e)


def read():
	try:
		employeeCollection = db.Employees.find()
		print('\nAll data from Employees database \n')
		
		for employee in employeeCollection:
			print(employee)
	
	except Exception as e:
		print(e)


def update():
	try:
		criteria = input('\nEnter id to update\n')
		name = input('\nEnter name to update\n')
		age = input('\nEnter age to update\n')
		country = input('\nEnter Country to update\n')

		db.Employees.update_one(
			{"id" : criteria},
			{"$set" : {
				"name" : name,
				"age" : age,
				"country" : country
				}
			}
		)

		print('\nRecords updated successfully\n')

	except Exception as e:
		print(e)


def delete():
	try:
		criteria = input('\nEnter employee id to delete\n')
		db.Employees.delete_many({"id" : criteria})
		print('\nDeletion successful\n')

	except Exception as e:
		print(e)	

if __name__ == "__main__":
	main()

