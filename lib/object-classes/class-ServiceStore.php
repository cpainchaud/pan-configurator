<?php

/*
 * Copyright (c) 2014-2015 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
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
class ServiceStore 
{
	use PathableName;
    use XmlConvertible;

    /**
     * @var PanoramaConf|PANConf|VirtualSystem|DeviceGroup
     */
	public $owner;

	/**
	 * @var null|ServiceStore
	 */
	public $parentCentralStore = null;
	
	protected $appdef = false;

	/**
	 * @var Service[]|ServiceGroup[]
	 */
	protected $all = Array();

	/**
	 * @var Service[]
	 */
	protected $_serviceObjects = Array();
	/**
	 * @var ServiceGroup[]
	 */
	protected $_serviceGroups = Array();
	/**
	 * @var Service[]
	 */
	protected $_tmpServices = Array();
	
	protected $fast = Array(); 
	protected $fastMemToIndex = null;

    /**
     * @var DOMElement
     */
	public $serviceRoot;
    /**
     * @var DOMElement
     */
	public $serviceGroupRoot;
	
	
	public function __construct($owner)
	{
		$this->owner = $owner;

        if( isset($owner->parentDeviceGroup) && $owner->parentDeviceGroup !== null )
            $this->parentCentralStore = $owner->parentDeviceGroup->serviceStore;
		else
            $this->findParentCentralStore();
		
		$this->regen_Indexes();
	}


	/**
	*
	*
	*/
	public function load_services_from_domxml($xml)
	{
		$this->serviceRoot = $xml;

		foreach( $this->serviceRoot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new Service('',$this);
			$ns->load_from_domxml($node);
			//print $this->toString()." : new service '".$ns->name."' created\n";
			$this->_serviceObjects[] = $ns;
			$this->all[] = $ns;
			$this->add_Obj_inIndex( $ns,lastIndex($this->all));
		}

		
		$this->regen_Indexes();
	}
	
	
	private function remergeAll()
	{
		
		$this->all = array_merge($this->_serviceObjects, $this->_serviceGroups, $this->_tmpServices);
		
		
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
		return $this->_serviceObjects;
	}

	/**
	 * @return ServiceGroup[]
	 */
	public function serviceGroups()
	{
		return $this->_serviceGroups;
	}

	/**
	 * @return Service[]
	 */
	public function serviceTmpObjects()
	{
		return $this->_tmpServices;
	}


    /**
     * @param $xml DOMElement
     */
	public function load_servicegroups_from_domxml($xml)
	{
		$this->serviceGroupRoot = $xml;
		
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;

			$ns = new ServiceGroup('',$this);
			$ns->load_from_domxml($node);
			
			$f = $this->findTmpService($ns->name());
			if( $f )
			{
				$f->replaceMeGlobally($ns);
                $this->remove($f);
			}
			$this->_serviceGroups[] = $ns;
			$this->all[] = $ns; 
			$this->add_Obj_inIndex($ns,lastIndex($this->all));
		}
		
		$this->regen_Indexes();
	}


	public function count()
	{
		return count($this->all);
	}

	
	/**
	* returns the count of ServiceGroups in this store
	*
	*/
	public function countServiceGroups()
	{
	
		return count($this->_serviceGroups);
	}

    /**
     * returns the count of Services (ie not groups) in this store
     *
     */
	public function countServices()
	{
		return count($this->_serviceObjects);
	}
	
	
	public function countTmpServices()
	{
		return count($this->_tmpServices);
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
			while( isset($curo->owner) && $curo->owner !== null )
			{
				
				if( isset($curo->owner->serviceStore) &&
					$curo->owner->serviceStore !== null				)
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

    /**
     * @param string $fn
     * @param null $ref
     * @param bool $nested
     * @param string $type
     * @return null|Service|ServiceGroup
     */
	public function find( $fn , $ref=null, $nested=true, $type = '')
	{
		$f = null;

        if( $type == 'tmp' )
        {
            $a = &$this->_tmpServices;
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

            if( $f !== null )
                return $f;
        }
        else if( $nested && isset($this->panoramaDG) )
        {
            $f = $this->panoramaDG->find( $fn , $ref, false, $type);
            if( $f !== null )
                return $f;
        }


        if( $nested && $this->parentCentralStore !== null )
        {

            $f = $this->parentCentralStore->find( $fn , $ref, $nested);
        }


        return $f;

	}

    /**
     * @param $fn
     * @param null $ref
     * @param bool|true $nested
     * @return null|Service|ServiceGroup
     */
	public function findOrCreate( $fn , $ref=null, $nested=true)
	{
        $f = $this->find( $fn , $ref, $nested);
        if( $f )
            return $f;

        $f = $this->createTmp($fn,$ref);

        return $f;
	}

    /**
     * @param $name
     * @return null|Service
     */
	public function findTmpService($name)
	{
		return $this->find($name , null, false, 'tmp');
	}


	/**
	 * @param Service|ServiceGroup $s
	 * @param bool $cleanInMemory
	 * @return bool
	 */
	public function remove($s, $cleanInMemory = false)
	{
		$class = get_class($s);
		
		$ser = spl_object_hash($s);
		
		if( isset($this->fastMemToIndex[$ser]))
		{
			if( $class == "Service" )
			{
				if( $s->type == 'tmp' )
				{
					$pos = array_search($s, $this->_tmpServices,true);
					unset($this->_tmpServices[$pos]);

				}
				else
				{
					$pos = array_search($s, $this->_serviceObjects,true);
					unset($this->_serviceObjects[$pos]);
				}
			}
			else if( $class == "ServiceGroup" )
			{
				$pos = array_search($s, $this->_serviceGroups,true);
				unset($this->_serviceGroups[$pos]);
                if( $cleanInMemory )
                    $s->removeAll(false);
			}
			else
				derr("Class $class is not supported");
				
			unset($this->fast[$s->name()]);
			unset($this->all[$this->fastMemToIndex[$ser]]);
			unset($this->fastMemToIndex[$ser]);

			$s->owner = null;

			if( !$s->isTmpSrv() )
			{
				if( $class == "Service" )
				{
                    if( count($this->_serviceObjects) > 0 )
                        $this->serviceRoot->removeChild($s->xmlroot);
                    else
                        DH::clearDomNodeChilds($this->serviceRoot);
				}
				else if( $class == "ServiceGroup" )
                {
                    if( count($this->_serviceGroups) > 0 )
                        $this->serviceGroupRoot->removeChild($s->xmlroot);
                    else
                        DH::clearDomNodeChilds($this->serviceGroupRoot);
                }
                else
                    derr('unsupported');

                if( $cleanInMemory )
                    $s->xmlroot = null;
			}
			return true;
		}
		return false;
	}

	/**
	 * @param Service|ServiceGroup $s
	 * @return bool
	 */
	public function API_remove($s, $cleanInMemory = false)
	{
		$xpath = null;

		if( !$s->isTmpSrv() )
			$xpath = $s->getXPath();

		$ret = $this->remove($s, $cleanInMemory);

		if( $ret && !$s->isTmpSrv())
		{
			$con = findConnectorOrDie($this);
			$con->sendDeleteRequest($xpath);
		}

		return $ret;
	}

	
	public function rewriteServiceStoreXML()
	{
		DH::clearDomNodeChilds($this->serviceRoot);
		foreach( $this->_serviceObjects as $s )
		{
			$this->serviceRoot->appendChild($s->xmlroot);
		}
	}

	public function rewriteServiceGroupStoreXML()
	{
		DH::clearDomNodeChilds($this->serviceGroupRoot);
		foreach( $this->_serviceGroups as $s )
		{
			$this->serviceGroupRoot->appendChild($s->xmlroot);
		}
	}

    /**
     * @param Service|ServiceGroup $s
     * @param bool $rewritexml
     * @throws Exception
     */
	public function add($s, $rewritexml=true)
	{
		//print "Service->add was called\n";

		if( $s === null )
			derr('attempt to add null object?');

		$class = get_class($s);
		
		$ser = spl_object_hash($s);
		
		if( !isset($this->fastMemToIndex[$ser]) && !isset($this->fast[$s->name()]) )
		{
			//print "Service->add was continued\n";
			
			if( $class == 'Service' )
			{
				if( $s->type == 'tmp' )
					$this->_tmpServices[] = $s;
				else
				{
					$this->_serviceObjects[] = $s;
				}
	
			}
			elseif ( $class == 'ServiceGroup' )
			{
				$this->_serviceGroups[] = $s;
				
			}
			else
				derr('invalid class found');
			
			$this->all[] = $s;
			$this->fast[$s->name()] = $s;
			$this->fastMemToIndex[$ser] = lastIndex($this->all);
				

			$s->owner = $this;

			if( $rewritexml )
			{
				if( $class == "Service" )
					$this->rewriteServiceStoreXML();
				else if( $class == "ServiceGroup" )
					$this->rewriteServiceGroupStoreXML();
			}
		}
	}

	private function &getBaseXPath()
	{
		$str = '';

		if ($this->owner->isPanorama() ||  $this->owner->isFirewall() )
		{
			$str = "/config/shared";
		}
		else
			$str = $this->owner->getXPath();


		return $str;
	}

	public function &getServiceStoreXPath()
	{
		$path = $this->getBaseXPath().'/service';
		return $path;
	}

	public function &getServiceGroupStoreXPath()
	{
		$path = $this->getBaseXPath().'/service-group';
		return $path;
	}

	
	public function newService($name, $protocol, $destinationPorts)
	{
		
		if( isset($this->fast[$name]) )
			derr("A Service named '$name' already exists");
		
		$s = new Service($name, $this, true);
		$s->setProtocol($protocol);
		$s->setDestPort($destinationPorts);
		$this->add($s);
		return $s;
	
	}
	
	function createTmp($name, $ref=null)
	{
		$f = new Service($name,$this);
		$this->_tmpServices[] = $f;
		$this->all[] = $f;
		$f->type = 'tmp';
		$f->addReference($ref);
		$this->fast[$f->name()] = $f;
		$this->fastMemToIndex[spl_object_hash($f)] = lastIndex($this->all);
		
		return $f;
	}
	
	
	public function referencedObjectRenamed($h,$oldname)
	{

        if( $this->fast[$oldname] !== $h)
        {
            mwarning("Unexpected : object is not part of this library");
            return false;
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
		if( $object === null )
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
		foreach( $this->_serviceObjects as $o )
		{
			if( $o->countReferences() == 0 )
				$count++;
		}

		return $count;
	}

	public function countUnusedServiceGroups()
	{
		$count = 0;
		foreach( $this->_serviceGroups as $o )
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
			while( isset($curo->owner) && $curo->owner !== null )
			{
				
				if( isset($curo->owner->serviceStore) &&
					$curo->owner->serviceStore !== null				)
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


