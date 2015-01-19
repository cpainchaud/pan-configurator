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
class ServiceStore 
{
	use PathableName;
	
	public $owner;
	
	protected $centralStore = false;

	/**
	 * @var null|ServiceStore
	 */
	protected $parentCentralStore = null;
	
	protected $appdef = false;
	
	protected $all = Array();
	
	protected $serv = Array();
	protected $servg = Array();
	protected $tmpserv = Array();
	
	protected $fast = Array(); 
	protected $fastMemToIndex = null;
	protected $fasthashcomp = null;
	
	public $servroot;
	public $servgroot;
	
	
	public function ServiceStore($owner, $centralrole=false)
	{
		$this->fasthashcomp = null;
		
		$this->owner = $owner;
		$this->centralStore = $centralrole;
		$this->findParentCentralStore();
		
		$this->regen_Indexes();
		
	}
	
	
	
	/**
	*
	*
	*/
	public function load_services_from_xml(&$xml)
	{
		$this->fasthashcomp = null;

        if( !isset($this->version) )
        {
            if( !isset($this->owner->version) || $this->owner->version === null  )
                derr('cannot find PANOS version from parent object');

            $this->version = $this->owner->version;
        }
		
		$this->servroot = &$xml;
		
		foreach( $xml['children'] as &$cur)
		{
			$ns = new Service('',$this);
			$ns->load_from_xml($cur);
			//print $this->toString()." : new service '".$ns->name."' created\n";
			$this->serv[] = $ns;
			$this->all[] = $ns;
			$this->add_Obj_inIndex( $ns,lastIndex($this->all));
			
		}
		
		$this->regen_Indexes();
	}


	/**
	*
	*
	*/
	public function load_services_from_domxml($xml)
	{
		$this->fasthashcomp = null;
		
		$this->servroot = $xml;

		foreach( $this->servroot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new Service('',$this);
			$ns->load_from_domxml($node);
			//print $this->toString()." : new service '".$ns->name."' created\n";
			$this->serv[] = $ns;
			$this->all[] = $ns;
			$this->add_Obj_inIndex( $ns,lastIndex($this->all));
		}

		
		$this->regen_Indexes();
	}
	
	
	private function remergeAll()
	{
		
		$this->all = array_merge($this->serv, $this->servg, $this->tmpserv);
		
		
		$this->regen_Indexes();
	}

	public function isAny()
	{
		if( !$this->appdef && $this->count() == 0 )
			return true;

		return false;
	}

	public function isApplicationDefault()
	{
		if($this->appdef)
			return true;

		return false;
	}

	/**
	 * @return Service[]|ServiceGroup[]
	 */
	public function all()
	{
		return $this->all;
	}

	/**
	 * @return Service[]
	 */
	public function serviceObjects()
	{
		return $this->serv;
	}

	/**
	 * @return ServiceGroup[]
	 */
	public function serviceGroups()
	{
		return $this->servg;
	}
	
	
	public function load_servicegroups_from_xml(&$xml)
	{
		
		$this->fasthashcomp = null;

        if( !isset($this->version) )
        {
            if( !isset($this->owner->version) || $this->owner->version === null  )
                derr('cannot find PANOS version from parent object');

            $this->version = $this->owner->version;
        }
		
		$this->servgroot = &$xml;
		
		$cur = &$xml['children'];
		
		$c = count($cur);
		$k = array_keys($cur);
		
		for( $i=0; $i<$c; $i++ )
		{
			$ns = new ServiceGroup('',$this);
			$ns->load_from_xml($cur[$k[$i]]);
			
			$f = $this->findTmpService($ns->name(), null,false);
			if( $f )
			{
				$f->replaceMeGlobally($ns);
				
			}
			$this->servg[] = $ns;
			$this->all[] = $ns; 
			$this->add_Obj_inIndex($ns,lastIndex($this->all));
		}
		
		$this->regen_Indexes();
	}


	public function load_servicegroups_from_domxml($xml)
	{
		
		$this->fasthashcomp = null;
		
		$this->servgroot = $xml;
		
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new ServiceGroup('',$this);
			$ns->load_from_domxml($node);
			
			$f = $this->findTmpService($ns->name(), null,false);
			if( $f )
			{
				$f->replaceMeGlobally($ns);
				
			}
			$this->servg[] = $ns;
			$this->all[] = $ns; 
			$this->add_Obj_inIndex($ns,lastIndex($this->all));
		}
		
		$this->regen_Indexes();
	}

	public function hasObject($object, $caseSensitive = true)
	{
		if( $this->centralStore )
			derr('unsupported on central store');

		if( is_string($object) )
		{
			if( !$caseSensitive )
				$object = strtolower($object);

			foreach( $this->all as $o )
			{
				if( !$caseSensitive )
				{
					if ($object == strtolower($o->name()))
						return true;
				}
				else if( $object == $o->name() )
					return true;
			}

			return false;
		}
		else
			derr('unsupported');

		return false;
	}
	
	
	public function load_local_objects_xml(&$xml)
	{
		$this->fasthashcomp = null;
		
		if( $this->centralStore )
		{
			derr("Error cannot call this method from a store");
		}
		
		$this->xmlroot = &$xml;

		foreach($xml['children'] as &$cur)
		{
			$lname = $cur['content'];
			
			if( $i == 0 )
			{
				if( $lname == 'any' )
				{
					break;
				}
				if( $lname == 'application-default' )
				{
					$this->appdef = true;
					break;
				}
			}
			$f = $this->parentCentralStore->findOrCreate($lname);
			
			$f->refInRule($this);
			$this->all[] = $f;
			$this->add_Obj_inIndex($f, lastIndex($this->all));
		}
		
		$this->regen_Indexes();
		
	}

	public function load_local_objects_domxml($xml)
	{
		$this->fasthashcomp = null;
		
		if( $this->centralStore )
		{
			derr("Error cannot call this method from a store");
		}
		
		$this->xmlroot = $xml;
		
		$i=0;
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
			$lname = $node->textContent;
			
			if( $i == 0 )
			{
				if( $lname == 'any' )
				{
					break;
				}
				if( $lname == 'application-default' )
				{
					$this->appdef = true;
					break;
				}
			}
			$f = $this->parentCentralStore->findOrCreate($lname);
			
			$f->refInRule($this);
			$this->all[] = $f;
			$this->add_Obj_inIndex($f, lastIndex($this->all));
			$i++;
		}
		
		$this->regen_Indexes();
		
	}
	
	
	/**
	*
	*
	*/
	public function setCentralStoreRole($is)
	{
		$this->centralStore = $is;
	}
	
	
	/**
	*
	*
	*/
	public function count()
	{
		return count($this->all);
	}
	
	
	
	
	/**
	* returns the count of ServerGroups in this store
	*
	*/
	public function countServiceGroups()
	{
	
		return count($this->servg);
	}
	
	
	public function countServices()
	{
		return count($this->serv);
	}
	
	
	public function countTmpServices()
	{
		return count($this->tmpserv);
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
				
				if( isset($curo->owner->serviceStore) &&
					!is_null($curo->owner->serviceStore)				)
				{
					$this->parentCentralStore = $curo->owner->serviceStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$curo = $curo->owner;
			}
		}
		
		//print $this->toString().": no parent store found\n";

	}
	
	public function find( $fn , $ref=null, $nested=true, $type = '')
	{
		$f = null;
		if( $this->centralStore)
		{
			/*if( $type == 'tmp' )
				$a = &$this->tmpserv;
			else
				$a = &$this->all;
			*/
			
			if( $type == 'tmp' )
			{
				$a = &$this->tmpserv;
				foreach($a as $o)
				{
					if( $o->name() == $fn )
					{
						$o->refInRule($ref);
						return $o;
					}
				}
			}
			
			if( isset($this->fast[$fn] ) )
			{
				if( $ref )
					$this->fast[$fn]->refInRule($ref);
				return $this->fast[$fn];
			}


			if( $nested && isset($this->panoramaShared) )
			{
				$f = $this->panoramaShared->find( $fn , $ref, false, $type);

				if( !is_null($f) )
					return $f;
			}
			else if( $nested && isset($this->panoramaDG) )
			{
				$f = $this->panoramaDG->find( $fn , $ref, false, $type);
				if( !is_null($f) )
					return $f;
			}

			
			if( $nested && $this->parentCentralStore)
			{

				$f = $this->parentCentralStore->find( $fn , $ref, $nested);
			}
			
			
			return $f;
		}

		if( $nested )
			$f = $this->parentCentralStore->find( $fn , $ref, $nested, $type);
		
		return $f;
	}
	
	public function findOrCreate( $fn , $ref=null, $nested=true)
	{
		if( $this->centralStore)
		{
			$f = $this->find( $fn , $ref, $nested);
			if( $f )
				return $f;
			
			$f = $this->createTmp($fn,$ref);
			
			return $f;
		}
		
		$f = $this->parentCentralStore->findOrCreate( $fn , $ref, $nested);
		return $f;
	}
	
	public function findTmpService($name)
	{
		return $this->find($name , null, false, 'tmp');
	}
	
	public function displayTmpServices()
	{
		$this->servessStore->displayTmpServices();
	}
	
	
	public function toString_inline()
	{
		$arr = &$this->all;
		$c = count($arr);

		if( $this->appdef )
		{
			$ret = 'application-default';
			return $ret;
		}
		
		if( $c == 0 )
		{
			$ret = '*ANY*';
			return $ret;
		}
		
		$first = true;
		
		$ret = '';
		
		foreach ( $arr as $s )
		{
			if( $first)
			{
				$ret .= $s->name();
			}
			else
				$ret .= ','.$s->name();
			
			
			$first = false;
		}
		
		return $ret;
		
	}
	
	public function merge($other)
	{
		$this->fasthashcomp = null;
		
		if( $this->centralStore )
			derr("Should never be called from a Central Store");
		
		if( $this->appdef && !$other->appdef || !$this->appdef && $other->appdef  )
			derr("You cannot merge 'application-default' type service stores with app-default ones");
		
		if( $this->appdef && $other->appdef )
			return;
		
		if( count($this->all) == 0 && !$other->appdef )
			return;
		
		if( count($other->all) == 0  && !$other->appdef)
		{
			$this->setAny();
			return;
		}
		
		foreach($other->all as $s)
		{
			if( count($this->all) == 0 )
				break;
			$this->add($s);
		}
	}
	
	public function remove($s , $rewritexml=true)
	{	
		$this->fasthashcomp = null;
		$class = get_class($s);
		
		$ser = spl_object_hash($s);
		
		if( isset($this->fastMemToIndex[$ser]))
		{
			if( count($this->all) == 1 && !$this->centralStore )
			{
				derr("You cannot remove last service without risking to introduce Any implicitly");
			}
			if( $class == "Service" )
			{
				if( $s->type == 'tmp' )
				{
					$pos = array_search($s, $this->tmpserv,true);
					unset($this->tmpserv[$pos]);

				}
				else
				{
					$pos = array_search($s, $this->serv,true);
					unset($this->serv[$pos]);
				}
			}
			else if( $class == "ServiceGroup" )
			{
				$pos = array_search($s, $this->servg,true);
				unset($this->servg[$pos]);
			}
			else
				derr("Class $class is not supported");
				
			unset($this->fast[$s->name()]);
			unset($this->all[$this->fastMemToIndex[$ser]]);
			unset($this->fastMemToIndex[$ser]);

			if( !$this->centralStore )
				$s->unrefInRule($this);
			
			if( $rewritexml )
			{
				if( !$this->centralStore )
					$this->rewriteXML();
				else if( $class == "Service" )
				{
					$this->rewriteServiceStoreXML();
				}
				else if( $class == "ServiceGroup" )
					$this->rewriteServiceGroupStoreXML();
			}
			return true;
		}

		return false;
		
	}
	
	public function rewriteServiceStoreXML()
	{
		if( !$this->centralStore )
			derr('can be called only from a central store');


		if( PH::$UseDomXML === TRUE )
		{
			DH::clearDomNodeChilds($this->servroot);
			foreach( $this->serv as $s )
			{
				$this->servroot->appendChild($s->xmlroot);
			}
			return;
		}
		$this->servroot['children'] = Array();
		foreach( $this->serv as $s )
		{
			$this->servroot['children'][] = &$s->xmlroot;
		}
	}

	public function rewriteServiceGroupStoreXML()
	{
		if( !$this->centralStore )
			derr('can be called only from a central store');

		if( PH::$UseDomXML === TRUE )
		{
			DH::clearDomNodeChilds($this->servgroot);
			foreach( $this->servg as $s )
			{
				$this->servgroot->appendChild($s->xmlroot);
			}
			return;
		}
		$this->servgroot['children'] = Array();
		foreach( $this->servg as $s )
		{
			$this->servgroot['children'][] = &$s->xmlroot;
		}
	}
	
	
	public function add($s, $rewritexml=true)
	{
		//print "Service->add was called\n";

		if( is_null($s) )
			derr('attempt to add null object?');
		
		$this->fasthashcomp = null;
		$class = get_class($s);
		
		$ser = spl_object_hash($s);
		
		if( !isset($this->fastMemToIndex[$ser]) && !isset($this->fast[$s->name()]) )
		{
			//print "Service->add was continued\n";
			
			if( $class == 'Service' )
			{
				if( $s->type == 'tmp' )
					$this->tmpserv[] = $s;
				else
				{
					$this->serv[] = $s;
				}
	
			}
			elseif ( $class == 'ServiceGroup' )
			{
				$this->servg[] = $s;
				
			}
			else
				derr('invalid class found');
			
			$this->all[] = $s;
			$this->fast[$s->name()] = $s;
			$this->fastMemToIndex[$ser] = lastIndex($this->all);
				

			$s->owner = $this;
			

			if( $rewritexml )
			{
				if( !$this->centralStore )
					$this->rewriteXML();
				else if( $class == "Service" )
					$this->rewriteServiceStoreXML();
				else if( $class == "ServiceGroup" )
					$this->rewriteServiceGroupStoreXML();
			}
		}
	}

	public function &getXPath()
	{
		$str = '';

		if( $this->centralStore )
		{
			$str = '';

			$class = get_class($this->owner);

			if( $class == 'VirtualSystem' )
			{
				$str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$this->owner->name."']";
			}
			else if ($class == 'DeviceGroup' )
			{
				$str = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$this->owner->name."']";
			}
			else if ($class == 'PanoramaConf' ||  $class == 'PANConf' )
			{
				$str = "/config/devices/entry[@name='localhost.localdomain']/shared/";
			}
			else
				derr('unsupported mode');


			return $str;
		}
		else
		{
			$classname = get_class($this->owner);
			if( $classname == 'SecurityRule' )
			{
				$str = $this->owner->getXPath().'/'.$this->name;
				return $str;
			}
		}

		derr('not supported');
	}

	public function &getServiceStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getXPath().'/service';
		return $path;
	}

	public function &getServiceGroupStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getXPath().'/service-group';
		return $path;
	}
	
	public function rewriteXML()
	{

		if( !$this->centralStore )
		{
			if( PH::$UseDomXML === TRUE )
			{
				if( $this->appdef )
					DH::Hosts_to_xmlDom($this->xmlroot, $this->all, true, 'application-default');
				else
					DH::Hosts_to_xmlDom($this->xmlroot, $this->all);
			}
			else
			{
				if( $this->appdef )
				{
					Hosts_to_xmlA($this->xmlroot['children'], $this->all, true, 'application-default');
					vardump($this->xmlroot);
				}
				else
					Hosts_to_xmlA($this->xmlroot['children'], $this->all);
			}
			
			return;
		}
		
		derr($this->toString()." ".__FUNCTION__.": Error : cannot call this from a store\n");
	}
	
	public function newService($name, $proto, $dport)
	{
		$this->fasthashcomp = null;
		
		if( ! $this->centralStore )
		{
			derr("cannot call this from a store");
		}
		
		if( isset($this->fast[$name]) )
			derr("A Service named '$name' already exists");
		
		$s = new Service($name, null, true);
		$s->setProtocol($proto);
		$s->setDestPort($dport);
		$this->add($s);
		return $s;
	
	}
	
	function createTmp($name, $ref=null)
	{
		$this->fasthashcomp = null;
		
		if( !$this->centralStore )
			derr("You cannot create an object from this Store: '".$this->toString()."'\n");
		
		$f = new Service($name,$this);
		$this->tmpserv[] = $f;
		$this->all[] = $f;
		$f->type = 'tmp';
		$f->refInRule($ref);
		$this->fast[$f->name()] = $f;
		$this->fastMemToIndex[spl_object_hash($f)] = lastIndex($this->all);
		
		return $f;
	}
	
	
	public function hostChanged($h,$oldname)
	{

		if( ! $this->inStore($h) )
			return false;

		$this->fasthashcomp = null;

		if( ! $this->centralStore )
		{
			$this->rewriteXML();
			return true;
		}

		unset($this->fast[$oldname]);
		$this->fast[$h->name()] = $h;

		return true;

	}

	/**
	* returns true if $object is in this store. False if not
	* 
	*/
	public function inStore($object)
	{
		if( is_null($object) )
			derr('a NULL object, really ?');

		if( isset($this->fastMemToIndex[spl_object_hash($object)]) )
			return true;

		return false;

	}
	
	protected function regen_Indexes()
	{
		unset($this->fastMemToIndex);
		$this->fastMemToIndex = Array();
		
		foreach($this->all as $i=>$rule)
		{
			$this->fastMemToIndex[spl_object_hash($rule)] = $i ;
			$this->fast[$rule->name()] = $rule;
		}
	}
	
	protected function add_Obj_inIndex($f , $index)
	{
		$this->fast[$f->name()] = $f;
		$this->fastMemToIndex[spl_object_hash($f)] = $index;
	}
	
	public function setAny()
	{
		$this->fasthashcomp = null;
		
		foreach( $this->all as $s )
		{
			$s->unrefInRule($this);
		}
		$this->all = Array();
		$this->appdef = false;
		$this->regen_Indexes();
		$this->rewriteXML();

		return true;
	}

	public function setApplicationDefault()
	{
		if( $this->appdef === true )
			return false;

		$this->fasthashcomp = null;
		
		foreach( $this->all as $s )
		{
			$s->unrefInRule($this);
		}
		$this->all = Array();
		$this->appdef = true;
		$this->regen_Indexes();
		$this->rewriteXML();

		return true;
	}

	public function API_setApplicationDefault()
	{
		$ret = $this->setApplicationDefault();

		if( !$ret )
			return false;

		$con = findConnectorOrDie($this);
		$xpath = &$this->owner->getXPath();
		
		$con->sendDeleteRequest($xpath.'/service');

		$con->sendSetRequest($xpath.'/service', '<member>application-default</member>');

		return true;
	}

	public function API_setAny()
	{
		$ret = $this->setAny();

		if( !$ret )
			return false;

		$con = findConnectorOrDie($this);
		$xpath = &$this->owner->getXPath();
		
		$con->sendDeleteRequest($xpath.'/service');

		$con->sendSetRequest($xpath.'/service', '<member>any</member>');

		return true;
	}
	
	
	
	public function equals( $other )
	{
		
		if( count($this->all) != count($other->all) )
			return false;
		
		if( $this->appdef != $other->appdef )
			return false;
		
		$indexes = array_keys($this->fast);
		
		foreach( $indexes as $index )
		{
			if( ! isset($other->fast[$index]) )
			{
				return false;
			}
			if( $other->fast[$index] === $this->fast[$index] )
			{
			}
			else
				return false;
		}
		
		
		return true;
	}
	
	public function equals_fasterHash( $other )
	{
		if( is_null($this->fasthashcomp) )
		{
			$this->generateFastHashComp();
		}
		if( is_null($other->fasthashcomp) )
		{
			$other->generateFastHashComp();
		}
		
		if( $this->fasthashcomp == $other->fasthashcomp  )
		{
			if( $this->equals($other) )
				return true;
		}
		
		return false;
	}
	
	public function replaceHostObject($old, $new)
	{
		if( is_null($old) )
			derr("\$old cannot be null");
		
		
		
		$class = get_class($new);
		
		if( !is_null($new) && $class != 'Service' && $class != 'ServiceGroup' )
			derr("New Object has wrong class type: $class");
		
		if( $this->centralStore )
		{
			derr("Calling this function in a Central Store should never happen");
		}
		else
		{
			if( !isset($this->fastMemToIndex[spl_object_hash($old)]) )
				derr("Object you want to replace was not found");
				
			if( !is_null($new) )
				$this->add($new,false);
			$this->remove($old);
		}
	}
	
	
	public function generateFastHashComp($force=false)
	{
		if( !is_null($this->fasthashcomp) && !$force )
			return;
		
		$fasthashcomp = 'ServiceStore';
		if( $this->appdef )
			$fasthashcomp .= 'appdef';	
		
		$tmpa = $this->all;
		
		usort($tmpa, "__CmpObjName");
		
		foreach( $tmpa as $o )
		{
			$fasthashcomp .= '.*/'.$o->name();
		}
		
		$this->fasthashcomp = md5($fasthashcomp,true);
		unset($fasthashcomp);
		
	}
	
	public function getFastHashComp()
	{
		$this->generateFastHashComp();
		return $this->fasthashcomp;
	}

	/**
	* To determine if a store has all the Service from another store, it will expand Service instead of looking for them directly. Very useful when looking to compare similar rules.
	* @return boolean true if Service objects from $other are all in this store
	*/
	public function includesStoreExpanded(ServiceStore $other, $anyIsAcceptable=true )
	{
		if( $this->centralStore )
			derr("Should never be called from a Central Store");

		if( !$anyIsAcceptable )
		{
			if( $this->count() == 0 || $other->count() == 0 )
				return false;
		}

		if( $this->count() == 0 )
			return true;

		if( $other->count() == 0 )
			return false;

		$localA = Array();
		$A = Array();

		foreach( $this->all as $object )
		{
			if( $object->isGroup() )
			{
				$flat = $object->expand();
				$localA = array_merge($localA, $flat);
			}
			else
				$localA[] = $object;
		}
		$localA = array_unique_no_cast($localA);

		$otherAll = $other->all();

		foreach( $otherAll as $object )
		{
			if( $object->isGroup() )
			{
				$flat = $object->expand();
				$A = array_merge($A, $flat);
			}
			else
				$A[] = $object;
		}
		$A = array_unique_no_cast($A);

		$diff = array_diff_no_cast($A, $localA);

		if( count($diff) > 0 )
		{
			return false;
		}
		

		return true;

	}

	
}


trait centralServiceStore
{
    /**
     * @var ServiceStore
     */
	public $serviceStore=null;
	
	public function serviceStore()
	{
		return $this->serviceStore;
	}
}


trait centralServiceStoreUser
{
	protected $parentServiceStore=null;
	
	public function findParentServiceStore()
	{
		$this->parentServiceStore = null;
		
		if( $this->owner )
		{
			$curo = $this;
			while( isset($curo->owner) && !is_null($curo->owner) )
			{
				
				if( isset($curo->owner->serviceStore) &&
					!is_null($curo->owner->serviceStore)				)
				{
					$this->parentServiceStore = $curo->owner->serviceStore;
					//print $this->toString()." : found a parent central store: ".$parentCentralStore->toString()."\n";
					return;
				}
				$curo = $curo->owner;
			}
		}
		//die($this->toString()." : not found parent central store: \n");
					
	}
}


