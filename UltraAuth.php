<?php

class UltraAuth
{
	private $db_type = 'sqlite';
	private $db_path = "./users.db";
	private $db = null;
	
	private $messages = array();
	
	private $username = "";
	
	private $login_url = "";
	
	private function createDatabaseConnection()
	{
		try
		{
			$db = new PDO($db_type . ':' . $db_path);
			return true;
		}
		catch(PDOException $e)
		{
			$this->messages[] = "PDO database connection error: " . $e->getMessage();
		}
		catch(Exception $e)
		{
			$this->messages[] = "General errors: " . $e->getMessage();
		}
		return false;
	}
	
	public function checkAuthentication()
	{
		session_start();
		if(!($this->checkLoggedIn()))
		{
			header("Location: $this->login_url");
		}
		
	}
	
	public function destroyLogin()
	{
		session_start();
		unset($_SESSION['user_name']);
		session_destroy();
		header("Location: $this->login_url");
	}
	
	public function registerUser($username, $password, $email)
	{
		$this->messages = array();
		if(isValidUsername($username))
		{
			if(isUniqueUsername($username) && isUniqueEmail($email))
			{
				$salt = md5(time() . $username . $email);
				$hashed_password = $this->generateHashedPassword($password, $salt);
				
				$query = "INSERT INTO users (username, password, salt, email, registered)
					VALUES(:username, :password, :salt, :email, :registered)";
				$stmt = $db->prepare($query);
				$stmt->bindValue(':username', $username);
				$stmt->bindValue(':password', $hashed_password);
				$stmt->bindValue(':salt', $salt);
				$stmt->bindValue(':email', $email);
				$stmt->bindValue(':registered', date('Y-m-d H:i:s'));
				
				$result = $stmt->execute();
				
				if($result)
				{
					$this->messages[] = "User registered successfully";
					return true;
				}
				else
				{
					$this->messages[] = "Error inserting user into database";
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	
	public function logIn($username, $password)
	{
		$query = "SELECT username, password, salt
			FROM users
			WHERE username = :username";
		$stmt = $db->prepare($query);
		$stmt->execute(array(":username" => $username));
		
		$result = $stmt->fetch();
		if($result)
		{
			if(checkHashedPassword($password, $result['salt'], $result['password']))
			{
				session_start();
				$this->username = $username;
				$this->createUserSession();
			}
			else
			{
				$this->messages[] = "Password is invalid"
				return false;
			}
		}
		else
		{
			$this->messages[] = "Username not found";
			return false;
		}
	}
	
	private function isValidUsername($username)
	{
		$valid_usernames = "/{3,3}[a-zA-Z]{1,4}[0-9]/";
		preg_match($valid_usernames, $username, $matches);
		
		if(isset($matches[0]))
		{
			return true;
		}
		else
		{
			$this->messages[] = "Username is not valid";
			return false;
		}
	}
	
	private function isUniqueUsername($username)
	{
		$query = "SELECT username
			FROM users
			WHERE username = :username";
		$stmt = $db->prepare($query);
		$stmt->execute(array(":username" => $username));
		
		$result = $stmt->fetch();
		
		if($result)
		{
			$this->messages[] = "Username is already associated with another account";
			return false;
		}
		else
		{
			return true;
		}
	}
	
	private function isUniqueEmail($email)
	{
		$query = "SELECT email
			FROM users
			WHERE email = :email";
		$stmt = $db->prepare($query);
		$stmt->execute(array(":email" => $email));
		
		$result = $stmt->fetch();
		
		if($result)
		{
			$this->messages[] = "Email address is already associated with another account";
			return false;
		}
		else
		{
			return true;
		}
	}
	
	private function generateHashedPassword($password, $salt)
	{
		return md5($password . $salt);
	}
	
	private function checkHashedPassword($raw_password, $salt, $hashed_password)
	{
		if(generateHashedPassword($raw_password, $salt) == $hashed_password)
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	private function createUserSession()
	{
		$_SESSION['user_name'] = $this->username;
	}
	
	private function checkLoggedIn()
	{
		if(isset($_SESSION['user_name']))
		{
			return true;
		}
		else
		{
			$this->messages[] = "No user currently logged in";
			return false;
		}
	}
}

?>
