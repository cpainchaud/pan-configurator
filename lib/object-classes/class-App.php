<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
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
	public $proto = null;
	
	//public $type = 'notfound';

 	public function App($name, $owner)
 	{
 		$this->owner = $owner;
		$this->name = $name;
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

 		if( is_null($this->proto) && is_null($this->icmp) && is_null($this->icmpsub) )
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

 		if( !is_null($this->tcp) )
 		{
 			foreach( $this->tcp as &$port )
 			{
 				if( $port[0] == 'dynamic' )
 					return true;
 			}
 		}

		if( !is_null($this->udp) )
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

 		if( is_null($proto) || is_null($port) )
 			derr('cannot be called with null arguments');

 		if( $proto != 'tcp' && $proto != 'udp' )
 			derr('unsupported procotol : '.$proto);

 		if( !is_null($this->$proto) )
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
	public function & calculateDependencies()
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
			foreach( $this->explicitUse as $explApp )
			{
				if( $explApp === $plusApp )
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
 	
	
}


