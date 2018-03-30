<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/


class App
{

	use ReferencableObject;
	use PathableName;

	public $type = 'tmp';

	public $tcp = null;
	public $udp = null;
	public $icmp = null;

	public $icmpsub = null;
    public $icmp6sub = null;
	public $proto = null;

	public $timeout = null;
    public $tcp_timeout = null;
    public $udp_timeout = null;
    public $tcp_half_closed_timeout = null;
    public $tcp_time_wait_timeout = null;

    /** @var null|array  */
    public $app_filter_details = null;

	/** @var null|string  */
	public $category = null;
	/** @var null|string  */
	public $subCategory = null;
    /** @var null|string  */
	public $technology = null;
    /** @var null|string  */
    public $risk = null;

    /** @var bool  */
    public $virusident = false;
    /** @var bool  */
    public $filetypeident = false;
    /** @var bool  */
    public $fileforward = false;

    /** @var bool  */
    public $custom_signature = false;

    /** @var string[]  */
    public $_characteristics = Array();
	
    static public $_supportedCharacteristics = Array(
        'evasive' => 'evasive',
        'excessive-bandwidth' => 'excessive-bandwidth',
        'prone-to-misuse' => 'prone-to-misuse',
        'saas' => 'saas',
        'transfers-files' => 'transfers-files',
        'tunnels-other-apps' => 'tunnels-other-apps',
        'used-by-malware' => 'used-by-malware',
        'vulnerabilities' => 'vulnerabilities',
        'widely-used' => 'widely-used'
        );
	
	//public $type = 'notfound';

 	public function __construct($name, $owner)
 	{
 		$this->owner = $owner;
		$this->name = $name;

		foreach( self::$_supportedCharacteristics as $characteristicName )
		    $this->_characteristics[$characteristicName] = false;
 	}

 	public function isUsingSpecialProto()
 	{

 		if( $this->isContainer() )
 		{
 			foreach( $this->subapps as $app )
 			{
 				if( $app->isUsingSpecialProto() )
 					return true;
 			}
 			return false;
 		}

 		if( $this->proto === null && $this->icmp === null && $this->icmpsub === null )
 			return false;

 		return true;
 	}

 	public function isContainer()
 	{
 		if( isset($this->subapps) )
 			return true;

 		return false;
 	}

 	public function containerApps()
 	{
 		if( !$this->isContainer() )
 			derr('cannot be be called on a non container app');

 		return $this->subapps;
 	}

	/**
	 * returns true if application is using dynamic ports
	 * @return bool
	 */
 	public function useDynamicPorts()
 	{

 		if( $this->isContainer() )
 		{
 			foreach( $this->subapps as $app )
 			{
 				if( $app->useDynamicPorts() )
 					return true;
 			}
 			return false;
 		}

 		if( $this->tcp !== null )
 		{
 			foreach( $this->tcp as &$port )
 			{
 				if( $port[0] == 'dynamic' )
 					return true;
 			}
 		}

		if( $this->udp !== null )
 		{
 			foreach( $this->udp as &$port )
 			{
 				if( $port[0] == 'dynamic' )
 					return true;
 			}
 		}

 		return false;
 	}

 	public function matchPort($proto, $port)
 	{

 		if( $this->isContainer() )
 		{
 			foreach( $this->subapps as $app )
 			{
 				if( $app->matchPort($proto, $port) )
 					return true;
 			}
 			return false;
 		}

 		if( $proto === null || $port === null )
 			derr('cannot be called with null arguments');

 		if( $proto != 'tcp' && $proto != 'udp' )
 			derr('unsupported procotol : '.$proto);

 		if( $this->$proto !== null )
 		{
 			foreach( $this->$proto as &$lport )
 			{
 				if( $lport[0] == 'single' && $lport[1] == $port  )
 					return true;
 				if( $lport[0] == 'range' && $port >= $lport[1] && $port <= $lport[2] )
 					return true;
 			}
 		}

 		return false;
 	}

	/**
	 * will return a list of dependencies and remove the 'implicit' ones
	 * @return App[]
	 */
	public function &calculateDependencies()
	{
		$ret = Array();

		if( isset($this->explicitUse) )
			$plus = $this->explicitUse;
		else
			$plus = Array();

		if( !isset($this->implicitUse) )
			return $plus;

		foreach( $plus as $plusApp )
		{
			$found = false;
            foreach( $this->implicitUse as $implApp )
            {
                if( $implApp === $plusApp )
                {
                    $found = true;
                    break;
                }
            }
			if( !$found )
				$ret[] = $plusApp;
		}

		return $ret;
	}

    public function isCustom()
    {
        if( $this->type == 'application-custom' )
            return true;

        return false;
    }

    public function CustomHasSignature()
    {
        if( $this->isCustom() )
            if( $this->custom_signature )
                return true;

        return false;
    }
}


