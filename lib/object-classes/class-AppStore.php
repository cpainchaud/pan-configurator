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

class AppStore
{
    use PathableName;

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null */
    public $owner;

    /** @var Application[] */
	protected $_all = Array();

    /** @var Application[] */
    protected $_applications = Array();

    /** @var ApplicationGroup[] */
    protected $_groups = Array();

    /** @var ApplicationFilter[] */
    protected $_filters = Array();

    /** @var Application[] */
    protected $_tmpApplications = Array();

    /** @var AppStore */
	public $parentCentralStore = null;

    /** @var null|AppStore  */
    protected static $predefinedStore = null;

    /** @var DOMElement */
    public $applicationsRoot;

    /** @var DOMElement */
    public $groupsRoot;

    /** @var DOMElement */
    public $filtersRoot;


    /**
     * @return AppStore|null
     */
    public static function getPredefinedStore()
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new AppStore(null);
        self::$predefinedStore->name = 'predefined Apps';
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }
	
	public function __construct($owner)
	{
		$this->owner = $owner;
	}

    /**
     * @param $objectName string
     * @param $ref
     * @return null|Application
     */
	public function find($objectName, $ref=null, $nested)
	{

        if( isset($this->_all[$objectName]) )
        {
            $foundObject = $this->_all[$objectName];
            $foundObject->addReference($ref);
            return $foundObject;
        }

        if( $nested && $this->parentCentralStore !== null )
        {
            $f = $this->parentCentralStore->find( $objectName , $ref, $nested);
            return $f;
        }

        return null;
	}


    /**
     * @param string $objectName
     * @param null $ref
     * @param bool $nested
     * @return Application|null
     */
    public function findOrCreate($objectName, $ref=null, $nested=true)
    {
        $f = $this->find( $objectName , $ref, $nested);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($objectName,$ref);

        return $f;
    }


    /**
     * @param string $objectName
     * @param null $ref
     * @return Application
     */
    public function createTmp($objectName, $ref=null)
    {
        if( isset($this->_all[$objectName]) )
        {
            mwarning("cannot create a TMP object  name '{$objectName}' in store that already exists");
            return $this->_all[$objectName];
        }

        $f = new Application($objectName,$this);

        $this->add($f);
        $f->addReference($ref);

        return $f;
    }

    /**
     * @param Application|ApplicationGroup|ApplicationFilter $s
     * @return bool
     * @throws Exception
     */
    public function add($s)
    {
        $objectName = $s->name();

        // there is already an object named like that
        if( isset($this->_all[$objectName]) && $this->_all[$objectName] !== $s )
        {
            derr('You cannot add object with same name in a store');
        }

        $class = get_class($s);

        if( $class == 'Address' )
        {
            if( $s->isTmp() )
            {
                $this->_tmpApplications[$objectName] = $s;
            }
            else
            {
                $this->_applications[$objectName] = $s;
                $this->applicationsRoot->appendChild($s->xmlroot);
            }

            $this->_all[$objectName] = $s;
        }
        elseif ( $class == 'AddressGroup' )
        {
            $this->_groups[$objectName] = $s;
            $this->_all[$objectName] = $s;
            $this->groupsRoot->appendChild($s->xmlroot);

        }
        else
            derr('invalid class found');


        $s->owner = $this;

        return true;
    }


	/**
	* return an array with all Apps in this store
	*
	*/
	public function apps()
	{
		return $this->_all;
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

				if( isset($curo->owner->appStore) &&
					$curo->owner->appStore !== null			)
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

    public function load_from_domxml( DOMElement $xml )
    {
        foreach ($xml->childNodes as $appx)
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;

            $appName= DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("app name not found\n");

            $app = new Application($appName, $this);
            $app->type = 'predefined';
            $this->add($app);

            $cursor = DH::findFirstElement('default', $appx);
            if ( $cursor === false )
                continue;

            $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
            if( $protocur !== false )
            {
                $app->proto = $protocur->textContent;
            }

            $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
            if( $icmpcur !== false )
            {
                $app->icmpsub = $icmpcur->textContent;
            }

            $cursor = DH::findFirstElement('port', $cursor);
            if( $cursor === false )
                continue;

            foreach( $cursor->childNodes as $portx )
            {
                if( $portx->nodeType != XML_ELEMENT_NODE )
                    continue;

                /** @var  $portx DOMElement */

                $ex = explode('/', $portx->textContent );

                if( count($ex) != 2 )
                    derr('unsupported port description: '.$portx->textContent);

                if( $ex[0] == 'tcp' )
                {
                    $exports = explode(',', $ex[1]);
                    $ports = Array();

                    if( count($exports) < 1 )
                        derr('unsupported port description: '.$portx->textContent);

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

                    if( $app->tcp === null )
                        $app->tcp = $ports;
                    else
                        $app->tcp = array_merge($app->tcp, $ports);
                }
                elseif( $ex[0] == 'udp' )
                {
                    $exports = explode(',', $ex[1]);
                    $ports = Array();

                    if( count($exports) < 1 )
                        derr('unsupported port description: '.$portx->textContent);

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

                    if( $app->udp === null )
                        $app->udp = $ports;
                    else
                        $app->udp = array_merge($app->udp, $ports);
                }
                elseif( $ex[0] == 'icmp' )
                {
                    $app->icmp = $ex[1];
                }
                else
                    derr('unsupported port description: '.$portx->textContent);


            }

            $cursor = DH::findFirstElement('use-applications', $appx);
            if( $cursor !== false )
            {
                foreach($cursor->childNodes as $depNode)
                {
                    if( $depNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $depName = $depNode->textContent;
                    if( strlen($depName) < 1 )
                        derr("dependency name length is < 0");
                    $depApp = $this->findOrCreate($depName);
                    $app->explicitUse[] = $depApp;
                }
            }

            $cursor = DH::findFirstElement('implicit-use-applications', $appx);
            if( $cursor !== false )
            {
                foreach($cursor->childNodes as $depNode)
                {
                    if( $depNode->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $depName = $depNode->textContent;
                    if( strlen($depName) < 1 )
                        derr("dependency name length is < 0");
                    $depApp = $this->findOrCreate($depName);
                    $app->implicitUse[] = $depApp;
                }
            }
        }

    }

	public function loadcontainers_from_domxml( &$xmlDom )
	{
		foreach( $xmlDom->childNodes as $appx )
		{
			if( $appx->nodeType != 1 ) continue;

			$app = new Application($appx->tagName, $this);
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
		if( $filename === null )
		{
			$filename = dirname(__FILE__).'/predefined.xml';
		}

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename);

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application', $xmlDoc);

		$this->load_from_domxml( $cursor );

        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application-container', $xmlDoc);

		$this->loadcontainers_from_domxml( $cursor );

		// fixing someone mess ;)
		$app = $this->findOrCreate('ftp');
		$app->tcp[] = Array( 0 => 'dynamic');
	}

}





