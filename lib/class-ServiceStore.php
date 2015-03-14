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

	/**
	 * @var Service[]|ServiceGroup[]
	 */
	protected $all = Array();

	/**
	 * @var Service[]
	 */
	protected $serv = Array();
	/**
	 * @var ServiceGroup[]
	 */
	protected $servg = Array();
	/**
	 * @var Service[]
	 */
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

	/**
	 * @return Service[]
	 */
	public function serviceTmpObjects()
	{
		return $this->tmpserv;
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
			
			$f->addReference($this);
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
			
			$f->addReference($this);
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
						$o->addReference($ref);
						return $o;
					}
				}
			}
			
			if( isset($this->fast[$fn] ) )
			{
				if( $ref !== null )
					$this->fast[$fn]->addReference($ref);
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

			
			if( $nested && $this->parentCentralStore !== null )
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

	/**
	 * @param Service|ServiceGroup $s
	 * @param bool $rewritexml
	 * @return bool
	 */
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

			$s->owner = null;

			if( $rewritexml )
			{
				if( $class == "Service" )
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

	/**
	 * @param Service|ServiceGroup $s
	 * @param bool $rewritexml
	 * @param bool $forceAny
	 * @return bool
	 */
	public function API_remove($s, $rewritexml = true, $forceAny = false)
	{
		$xpath = null;

		if( !$s->isTmpSrv() )
			$xpath = $s->getXPath();

		$ret = $this->remove($s, $rewritexml, $forceAny);

		if( $ret && !$s->isTmpSrv())
		{
			$con = findConnectorOrDie($this);
			$con->sendDeleteRequest($xpath);
		}

		return $ret;
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
			
			// TODO improve with atomic addition instead of rewriting everything
			// TODO cleanup central store stuff
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

	private function &getBaseXPath()
	{
		$str = '';

		$class = get_class($this->owner);

		if ($class == 'PanoramaConf' ||  $class == 'PANConf' )
		{
			$str = "/config/shared";
		}
		else
			$str = $this->owner->getXPath();


		return $str;
	}

	public function &getServiceStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getBaseXPath().'/service';
		return $path;
	}

	public function &getServiceGroupStoreXPath()
	{
		if( !$this->centralStore )
			derr('cannot be called from a non central store object');
		$path = $this->getBaseXPath().'/service-group';
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
		$f->addReference($ref);
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


	public function countUnused()
	{
		$count = 0;
		foreach( $this->all as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}

	public function countUnusedServices()
	{
		$count = 0;
		foreach( $this->serv as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}

	public function countUnusedServiceGroups()
	{
		$count = 0;
		foreach( $this->servg as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
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


