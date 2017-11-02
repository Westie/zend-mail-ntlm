<?php


namespace Westie\Zend\Mail\Protocol\Smtp\Auth;

use \Robin\Ntlm\Credential\Password;
use \Robin\Ntlm\Crypt\Des\OpenSslDesEncrypter;
use \Robin\Ntlm\Crypt\Hasher\HasherFactory;
use \Robin\Ntlm\Crypt\Random\NativeRandomByteGenerator;
use \Robin\Ntlm\Encoding\MbstringEncodingConverter;
use \Robin\Ntlm\Hasher\LmHasher;
use \Robin\Ntlm\Hasher\NtV1Hasher;
use \Robin\Ntlm\Message\ChallengeMessageDecoder;
use \Robin\Ntlm\Message\NegotiateFlag;
use \Robin\Ntlm\Message\NegotiateMessageEncoder;
use \Robin\Ntlm\Message\NtlmV1AuthenticateMessageEncoder;
use \Robin\Ntlm\Message\ServerChallenge;
use \Zend\Mail\Protocol\Exception\RuntimeException;
use \Zend\Mail\Protocol\Smtp;


/**
 *	Performs NTLM authentication
 */
class Ntlm extends Smtp
{
	/**
	 *	NTLM domain
	 */
	protected $domain = "";
	
	
	/**
	 *	NTLM hostname
	 */
	protected $hostname = "";
	
	
	/**
	 *	NTLM username
	 */
	protected $username;
	
	
	/**
	 * NTLM password
	 */
	protected $password;
	
	
	/**
	 *	Constructor
	 */
	public function __construct($host = '127.0.0.1', $port = null, $config = null)
	{
		$original_config = $config;
		
		if (is_array($host))
		{
			if (is_array($config))
				$config = array_replace_recursive($host, $config);
			else
				$config = $host;
		}
		
		if (is_array($config))
		{
			if (isset($config['domain']))
				$this->setDomain($config['domain']);
			
			if (isset($config['hostname']))
				$this->setHostname($config['hostname']);
			
			if (isset($config['username']))
				$this->setUsername($config['username']);
			
			if (isset($config['password']))
				$this->setPassword($config['password']);
		}
		
		parent::__construct($host, $port, $original_config);
	}
	
	
	/**
	 *	Perform PLAIN authentication with supplied credentials
	 */
	public function auth()
	{
		# Ensure AUTH has not already been initiated.
		parent::auth();
		
		# first step is to send out the negotiation message
		$this->_send('AUTH NTLM '.$this->getNtlmNegotiateMessage());
		
		# excellent, we now have our challenge.
		$input = $this->_expect(334);
		$server_challenge = $this->getNtlmServerChallenge($input);
		
		# and with this challenge, we need to send our response
		$this->_send($this->getNtlmV1AuthenticateMessage($server_challenge));
		$this->_expect(235);
		
		$this->auth = true;
	}
	
	
	/**
	 *  Set value for domain
	 */
	public function setDomain($domain)
	{
		$this->domain = $domain;
		return $this;
	}
	
	
	/**
	 *  Get domain
	 */
	public function getDomain()
	{
		return $this->domain;
	}
	
	
	/**
	 *  Set value for hostname
	 */
	public function setHostname($hostname)
	{
		$this->hostname = $hostname;
		return $this;
	}
	
	
	/**
	 *  Get hostname
	 */
	public function getHostname()
	{
		return $this->hostname;
	}
	
	
	/**
	 *  Set value for username
	 */
	public function setUsername($username)
	{
		$this->username = $username;
		return $this;
	}
	
	
	/**
	 *  Get username
	 */
	public function getUsername()
	{
		return $this->username;
	}
	
	
	/**
	 *  Set value for password
	 */
	public function setPassword($password)
	{
		$this->password = $password;
		return $this;
	}
	
	
	/**
	 *  Get password
	 */
	public function getPassword()
	{
		return $this->password;
	}
	
	
	/**
	 *	Retrieve negoation message
	 */
	protected function getNtlmNegotiateMessage()
	{
		$encoding_converter = new MbstringEncodingConverter();
		$encoder = new NegotiateMessageEncoder($encoding_converter);
		
		$output = $encoder->encode($this->domain, $this->hostname);
		
		return base64_encode($output);
	}
	
	
	/**
	 *	Retrieves the server challenge
	 */
	protected function getNtlmServerChallenge($input)
	{
		$decoder = new ChallengeMessageDecoder();
		
		$input = base64_decode($input);
		
		return $decoder->decode($input);
	}
	
	
	/**
	 *	Retrieves the authentication message using NTLMv1 protocol
	 */
	protected function getNtlmV1AuthenticateMessage(ServerChallenge $server_challenge)
	{
		$hasher_factory = HasherFactory::createWithDetectedSupportedAlgorithms();
		$encoding_converter = new MbstringEncodingConverter();
		$des_encrypter = new OpenSslDesEncrypter();
		$lm_hasher = new LmHasher($des_encrypter);
		$nt_hasher = new NtV1Hasher($hasher_factory, $encoding_converter);
		$byte_generator = new NativeRandomByteGenerator();
		
		$encoder = new NtlmV1AuthenticateMessageEncoder($encoding_converter, $lm_hasher, $nt_hasher, $byte_generator, $des_encrypter, $hasher_factory);
		
		$output = $encoder->encode($this->username, $this->domain, $this->hostname, new Password($this->password), $server_challenge);
		$output = base64_encode($output);
		
		return $output;
	}
}