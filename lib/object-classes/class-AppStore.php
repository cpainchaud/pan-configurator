<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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

class AppStore extends ObjStore
{
    /**
     * @var array|App[]
     */
	public $apps=Array();
	
	public $parentCentralStore = null;
	
	public static $childn = 'App';
	
	public function AppStore($owner)
	{
		$this->classn = &self::$childn;
		
		$this->owner = $owner;
		$this->o = &$this->apps;
		
		$this->findParentCentralStore();
	}

	public function find($name, $ref=null)
	{
		return $this->findByName($name,$ref);
	}


	/**
	* add a App to this store
	*
	*/
	public function addApp( App $Obj, $rewritexml = true )
	{
		if( $this->centralStore )
			derr('cannot be called from a central store');

		$fasthashcomp=null;

		$ret = $this->add($Obj);

		if( $ret && $rewritexml && !$this->centralStore)
		{
			$this->rewriteXML();
		}
		return $ret;

	}


	/**
	* add a App to this store
	*
	*/
	public function API_addApp( App $Obj, $rewritexml = true )
	{
		$ret = addApp($Obj, $rewritexml);

		if( !$ret )
			return false;

		$con = findConnectorOrDie($this);
		$xpath = &$this->owner->getXPath();

		if( $this->count() == 1)
		{
			$con->sendDeleteRequest($xpath.'/application');
		}

		$con->sendSetRequest($xpath.'/application', '<member>'.$Obj->name().'</member>');

		return true;
	}

	public function API_synchronize()
	{
		if( $this->centralStore )
			derr('cannot be called from a centralStore');

		$con = findConnectorOrDie($this);

		$xpath = &$this->owner->getXPath();
		$con->sendDeleteRequest($xpath.'/application');

		$element = &array_to_xml( $this->xmlroot, -1, false);
		$con->sendSetRequest($xpath, $element);
	}



	/**
	* remove an App to this store. Be careful if you remove last zone as
	* it would become 'any' and won't let you do so.
	 * @param App $Object
	* @param bool $rewriteXml
	* @param bool $forceAny
	 * @return bool
	*/
	public function removeApp( App $Object, $rewriteXml = true, $forceAny = false )
	{
		$count = count($this->o);

		$ret = $this->remove($Object);

		if( $ret && $count == 1 && !$forceAny && !$this->centralStore )
		{
			derr("you are trying to remove last App from a rule which will set it to ANY, please use forceAny=true for object: "
				 .$this->toString() ) ;
		}

		if( $ret && $rewriteXml && !$this->centralStore)
		{
			$this->rewriteXML();
		}
		return $ret;
	}

	/**
	* returns true if rule app is Any
	*
	*/
	public function isAny()
	{
		return  ( count($this->o) == 0 );
	}


	/**
	* return an array with all Apps in this store
	*
	*/
	public function apps()
	{
		return $this->o;
	}


	/**
	* should only be called from a Rule constructor
	* @ignore
	*/
	public function load_from_domxml(DOMElement $xml)
	{
		//print "started to extract '".$this->toString()."' from xml\n";
		$this->xmlroot = $xml;
		$i=0;
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			if( $i == 0 && strtolower($node->textContent) == 'any' )
			{
				return;
			}

			$f = $this->parentCentralStore->findOrCreate( $node->textContent, $this);
			$this->o[] = $f;
			$i++;
		}
	}




	/**
	*
	* @ignore
	*/
	protected function findParentCentralStore()
	{
		$this->parentCentralStore = null;

		if( $this->owner )
		{
			$curo = $this;
			while( isset($curo->owner) && !is_null($curo->owner) )
			{

				if( isset($curo->owner->appStore) &&
					!is_null($curo->owner->appStore)				)
				{
					$this->parentCentralStore = $curo->owner->appStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$curo = $curo->owner;
			}
		}

		//print $this->toString().": no parent store found\n";

	}


	public function load_from_xmlarr( &$xmlArr )
	{
		foreach( $xmlArr['children'] as &$appx )
		{
			$app = new App($appx['attributes']['name'], $this);
			$app->type = 'predefined';
			$this->add($app);

			$cursor = &searchForName('name', 'default', $appx['children'] );
			if( is_null($cursor) )
				continue;

			$protocur = &searchForName('name', 'ident-by-ip-protocol', $cursor['children'] );
			if( !is_null($protocur) )
			{
				$app->proto = $protocur['content'];
			}

			$icmpcur = &searchForName('name', 'ident-by-icmp-type', $cursor['children'] );
			if( !is_null($icmpcur) )
			{
				$app->icmpsub = $icmpcur['content'];
			}

			$cursor = &searchForName('name', 'port', $cursor['children'] );
			if( is_null($cursor) )
				continue;

			foreach( $cursor['children'] as &$portx )
			{
				$ex = explode('/', $portx['content'] );
				if( count($ex) != 2 )
					derr('unsupported port description: '.$portx['content']);
				if( $ex[0] == 'tcp' )
				{
					$exports = explode(',', $ex[1]);
					$ports = Array();

					if( count($exports) < 1 )
						derr('unsupported port description: '.$portx['content']);

					foreach( $exports as &$sport )
					{
						if( $sport == 'dynamic')
						{
							$ports[] = Array( 0 => 'dynamic' );
							continue;
						}
						$tmpex = explode('-', $sport);
						if( count($tmpex) < 2 )
						{
							$ports[] = Array( 0 => 'single' , 1 => $sport );
							continue;
						}

						$ports[] = Array( 0 => 'range' , 1 => $tmpex[0], 2 => $tmpex[1] );

					}
					//print_r($ports);

					if( is_null($app->tcp) )
						$app->tcp = $ports;
					else
						$app->tcp = array_merge($app->tcp, $ports);
				}
				elseif( $ex[0] == 'udp' )
				{
					$exports = explode(',', $ex[1]);
					$ports = Array();

					if( count($exports) < 1 )
						derr('unsupported port description: '.$portx['content']);

					foreach( $exports as &$sport )
					{
						if( $sport == 'dynamic')
						{
							$ports[] = Array( 0 => 'dynamic' );
							continue;
						}
						$tmpex = explode('-', $sport);
						if( count($tmpex) < 2 )
						{
							$ports[] = Array( 0 => 'single' , 1 => $sport );
							continue;
						}

						$ports[] = Array( 0 => 'range' , 1 => $tmpex[0], 2 => $tmpex[1] );

					}
					//print_r($ports);

					if( is_null($app->udp) )
						$app->udp = $ports;
					else
						$app->udp = array_merge($app->udp, $ports);
				}
				elseif( $ex[0] == 'icmp' )
				{
					$app->icmp = $ex[1];
				}
				else
					derr('unsupported port description: '.$portx['content']);


			}
		}
	}

	public function loadcontainers_from_xmlarr( &$xmlArr )
	{
		foreach( $xmlArr['children'] as &$appx )
		{
			$app = new App($appx['attributes']['name'], $this);
			$app->type = 'predefined';
			$this->add($app);

			$app->subapps = Array();

			//print "found container ".$app->name()."\n";

			$cursor = &searchForName('name', 'functions', $appx['children'] );
			if( is_null($cursor) )
				continue;

			foreach( $cursor['children'] as &$function)
			{
				$app->subapps[] = $this->findOrCreate($function['content']);
				//print "  subapp: ".$subapp->name()." type :".$subapp->type."\n";
			}


		}
	}

	public function loadcontainers_from_xmldom( &$xmlDom )
	{
		foreach( $xmlDom->childNodes as $appx )
		{
			if( $appx->nodeType != 1 ) continue;

			$app = new App($appx->tagName, $this);
			$app->type = 'predefined';
			$this->add($app);

			$app->subapps = Array();

			//print "found container ".$app->name()."\n";

			$cursor = DH::findFirstElement('functions', $appx );
			if( $cursor === FALSE )
				continue;

			foreach( $cursor->childNodes as $function)
			{
				$app->subapps[] = $this->findOrCreate($function->textContent);
				//print "  subapp: ".$subapp->name()." type :".$subapp->type."\n";
			}


		}
	}


	public function load_from_predefinedfile( $filename = null )
	{
		if( is_null($filename) )
		{
			$filename = dirname(__FILE__).'/predefined.xml';
		}
		$content = file_get_contents($filename);
		$xmlobj = new XmlArray();
		$xmlArr = &$xmlobj->load_string($content);
		unset($content);

		$cursor = &searchForName('name','application', $xmlArr['children']);

		if( is_null($cursor) )
			derr('could not find <application>');

		$this->load_from_xmlarr( $cursor );

		$cursor = &searchForName('name','application-container', $xmlArr['children']);
		if( !is_null($cursor) )
			$this->loadcontainers_from_xmlarr( $cursor );

		// fixing someone mess ;)
		$app = $this->findOrCreate('ftp');
		$app->tcp[] = Array( 0 => 'dynamic');
	}
	
	
}

trait centralAppStore
{
	/**
	 * @var AppStore
	 */
	public $appStore=null;
	
	public function appStore()
	{
		return $this->appStore;
	}
}




