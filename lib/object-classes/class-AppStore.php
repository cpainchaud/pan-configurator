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

class AppStore extends ObjStore
{
    /** @var array|App[] */
	public $apps=Array();
	
	public $parentCentralStore = null;
	
	public static $childn = 'App';

	public $predefinedStore_appid_version = null;

    /** @var null|AppStore  */
    public static $predefinedStore = null;

    /**
     * @return AppStore|null
     */
    public static function getPredefinedStore()
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new AppStore(null);
        self::$predefinedStore->setName('predefined Apps');
        self::$predefinedStore->load_from_predefinedfile();

        return self::$predefinedStore;
    }


	public function __construct($owner)
	{
		$this->classn = &self::$childn;
		
		$this->owner = $owner;
		$this->o = &$this->apps;
		
		$this->findParentCentralStore();
	}

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
	public function find($name, $ref=null)
	{
		return $this->findByName($name,$ref);
	}

    /**
     * @param $name string
     * @param $ref
     * @return null|App
     */
    public function findorCreate($name, $ref=null)
    {
        $f = $this->findByName($name,$ref);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($name, $ref);

        return $f;
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

            $app = new App($appName, $this);
            $app->type = 'predefined';
            $this->add($app);
        }

        foreach ($xml->childNodes as $appx)
        {

            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("app name not found\n");

            if( !isset($this->nameIndex[$appName]) )
                derr("Inconsistency problem : cannot match an application to its XML", $appx);

            $app = $this->nameIndex[$appName];

            #xpath /predefined/default
            $timeoutcur = DH::findFirstElement('timeout', $appx);
            if( $timeoutcur !== false )
            {
                $app->timeout = $timeoutcur->textContent;
            }
            $tcptimeoutcur = DH::findFirstElement('tcp-timeout', $appx);
            if( $tcptimeoutcur !== false )
            {
                $app->tcp_timeout = $tcptimeoutcur->textContent;
            }
            $udptimeoutcur = DH::findFirstElement('udp-timeout', $appx);
            if( $udptimeoutcur !== false )
            {
                $app->udp_timeout = $udptimeoutcur->textContent;
            }
            $tcp_half_timeoutcur = DH::findFirstElement('tcp-half-closed-timeout', $appx);
            if( $tcp_half_timeoutcur !== false )
            {
                $app->tcp_half_closed_timeout = $tcp_half_timeoutcur->textContent;
            }
            $tcp_wait_timeoutcur = DH::findFirstElement('tcp-time-wait-timeout', $appx);
            if( $tcp_wait_timeoutcur !== false )
            {
                $app->tcp_time_wait_timeout = $tcp_wait_timeoutcur->textContent;
            }

            $obsolete = DH::findFirstElement('obsolete', $appx);
            if( $obsolete !== false )
            {
                $app->obsolete = $obsolete->textContent;
            }


            #xpath /predefined
            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== false )
            {
                $app->category = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== false )
            {
                $app->subCategory = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== false )
            {
                $app->technology = $tmp->textContent;
            }


            $tmp = DH::findFirstElement('evasive-behavior', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = true;
            }
            $tmp = DH::findFirstElement('consume-big-bandwidth', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = true;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = true;
            }
            $tmp = DH::findFirstElement('able-to-transfer-file', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = true;
            }
            $tmp = DH::findFirstElement('has-known-vulnerability', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = true;
            }
            $tmp = DH::findFirstElement('tunnel-other-application', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = true;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = true;
            }
            $tmp = DH::findFirstElement('is-saas', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['saas'] = true;
            }
            $tmp = DH::findFirstElement('pervasive-use', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = true;
            }


            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== false )
            {
                $app->risk = $tmp->textContent;
            }
            $tmp = DH::findFirstElement('virusident-ident', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->virusident = true;
            }
            $tmp = DH::findFirstElement('filetype-ident', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->filetypeident = true;
            }
            $tmp = DH::findFirstElement('file-forward', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->fileforward = true;
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

            $cursor = DH::findFirstElement('default', $appx);
            if( $cursor === FALSE )
                continue;

            $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
            if( $protocur !== FALSE )
            {
                $app->proto = $protocur->textContent;
            }

            $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
            if( $icmpcur !== FALSE )
            {
                $app->icmpsub = $icmpcur->textContent;
            }

            $icmp6cur = DH::findFirstElement('ident-by-icmp6-type', $cursor);
            if( $icmp6cur !== FALSE )
            {
                $app->icmp6sub = $icmp6cur->textContent;
            }

            $cursor = DH::findFirstElement('port', $cursor);
            if( $cursor !== FALSE )
            {
                foreach( $cursor->childNodes as $portx )
                {
                    if( $portx->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /** @var  $portx DOMElement */

                    $ex = explode('/', $portx->textContent);

                    if( count($ex) != 2 )
                        derr('unsupported port description: ' . $portx->textContent);

                    if( $ex[0] == 'tcp' )
                    {
                        $exports = explode(',', $ex[1]);
                        $ports = Array();

                        if( count($exports) < 1 )
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = Array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = Array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = Array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

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
                            derr('unsupported port description: ' . $portx->textContent);

                        foreach( $exports as &$sport )
                        {
                            if( $sport == 'dynamic' )
                            {
                                $ports[] = Array(0 => 'dynamic');
                                continue;
                            }
                            $tmpex = explode('-', $sport);
                            if( count($tmpex) < 2 )
                            {
                                $ports[] = Array(0 => 'single', 1 => $sport);
                                continue;
                            }

                            $ports[] = Array(0 => 'range', 1 => $tmpex[0], 2 => $tmpex[1]);

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
                    elseif( $ex[0] == 'icmp6' )
                    {
                        $app->icmp6 = $ex[1];
                    }
                    else
                        derr('unsupported port description: ' . $portx->textContent);
                }
            }

        }
    }

	public function loadcontainers_from_domxml( &$xmlDom )
	{
		foreach( $xmlDom->childNodes as $appx )
		{
			if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName= DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationContainer name not found in XML: ", $appx);

            $app = new App($appName, $this);
			$app->type = 'predefined';
			$this->add($app);

			$app->subapps = Array();

			$cursor = DH::findFirstElement('functions', $appx );
			if( $cursor === FALSE )
				continue;

			foreach( $cursor->childNodes as $function)
			{
                if( $function->nodeType != XML_ELEMENT_NODE )
                    continue;

                $subapp = $this->findOrCreate($function->textContent);
                $app->subapps[] = $subapp;
			}

		}
	}

    public function load_application_group_from_domxml( $xmlDom )
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName= DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationGroup name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-group';
            $this->add($app);


            $app->groupapps = Array();

            $cursor = DH::findFirstElement('members', $appx );
            if( $cursor === FALSE )
                continue;

            foreach( $cursor->childNodes as $function)
            {
                if( $function->nodeType != XML_ELEMENT_NODE )
                    continue;

                $groupapp = $this->find($function->textContent);

                if( $groupapp !== null )
                    $app->groupapps[] = $groupapp;
                else
                {
                    $groupapp = $this->findOrCreate($function->textContent);
                    $app->groupapps[] = $groupapp;
                }
            }
        }
    }

    public function load_application_custom_from_domxml($xmlDom )
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationCustom name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-custom';
            $this->add($app);

            //TODO: not implemented yet: <description>custom_app</description>

            $signaturecur = DH::findFirstElement('signature', $appx);
            if( $signaturecur !== false )
            {
                $app->custom_signature = true;
            }

            $parentappcur = DH::findFirstElement('parent-app', $appx);
            if( $parentappcur !== false )
            {
                //TODO: implementation needed of $app->parent_app
                #$app->parent_app = $parentappcur->textContent;
            }

            $timeoutcur = DH::findFirstElement('timeout', $appx);
            if( $timeoutcur !== false )
            {
                $app->timeout = $timeoutcur->textContent;
            }
            $tcptimeoutcur = DH::findFirstElement('tcp-timeout', $appx);
            if( $tcptimeoutcur !== false )
            {
                $app->tcp_timeout = $tcptimeoutcur->textContent;
            }
            $udptimeoutcur = DH::findFirstElement('udp-timeout', $appx);
            if( $udptimeoutcur !== false )
            {
                $app->udp_timeout = $udptimeoutcur->textContent;
            }
            $tcp_half_timeoutcur = DH::findFirstElement('tcp-half-closed-timeout', $appx);
            if( $tcp_half_timeoutcur !== false )
            {
                $app->tcp_half_closed_timeout = $tcp_half_timeoutcur->textContent;
            }
            $tcp_wait_timeoutcur = DH::findFirstElement('tcp-time-wait-timeout', $appx);
            if( $tcp_wait_timeoutcur !== false )
            {
                $app->tcp_time_wait_timeout = $tcp_wait_timeoutcur->textContent;
            }

            $cursor = DH::findFirstElement('default', $appx);
            if( $cursor !== false )
            {
                $protocur = DH::findFirstElement('ident-by-ip-protocol', $cursor);
                if( $protocur !== false )
                {
                    $app->proto = $protocur->textContent;
                }

                $icmpcur = DH::findFirstElement('ident-by-icmp-type', $cursor);
                if( $icmpcur !== false )
                {
                    $icmptype = DH::findFirstElement('type', $icmpcur);
                    if( $icmptype !== false )
                    {
                        $app->icmpsub = $icmptype->textContent;
                    }
                    //TODO: <code>0</code>
                }

                $icmp6cur = DH::findFirstElement('ident-by-icmp6-type', $cursor);
                if( $icmp6cur !== false )
                {
                    $icmp6type = DH::findFirstElement('type', $icmp6cur);
                    if( $icmp6type !== false )
                    {
                        $app->icmp6sub = $icmp6type->textContent;
                    }
                    //TODO: <code>0</code>
                }

                $cursor = DH::findFirstElement('port', $cursor);
                if( $cursor !== false )
                {
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
                        elseif( $ex[0] == 'icmp6' )
                        {
                            $app->icmp6 = $ex[1];
                        }
                        else
                            derr('unsupported port description: '.$portx->textContent);
                    }
                }
            }


            $app->app_filter_details = array();

            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== false )
            {
                $app->category = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== false )
            {
                $app->subCategory = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== false )
            {
                $app->technology = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== false )
            {
                $app->risk = $tmp->textContent;
            }

            $tmp = DH::findFirstElement('evasive-behavior', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = true;
            }
            $tmp = DH::findFirstElement('consume-big-bandwidth', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = true;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = true;
            }
            $tmp = DH::findFirstElement('able-to-transfer-files', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = true;
            }
            $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = true;
            }
            $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = true;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = true;
            }

            $tmp = DH::findFirstElement('pervasive-use', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = true;
            }



            $tmp = DH::findFirstElement('virusident-ident', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->virusident = true;
            }
            $tmp = DH::findFirstElement('filetype-ident', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->filetypeident = true;
            }
            $tmp = DH::findFirstElement('data-ident', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->fileforward = true;
            }
        }
    }

    public function load_application_filter_from_domxml($xmlDom )
    {
        foreach( $xmlDom->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE ) continue;

            $appName= DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("ApplicationFilter name not found in XML: ", $appx);

            $app = new App($appName, $this);
            $app->type = 'application-filter';
            $this->add($app);

            //TODO: check if multiple selections are needed
            //only first FILTER is checked
            //what about second/third??
            //- if use array how to get the information via the app filter
            $app->app_filter_details = array();

            $tmp = DH::findFirstElement('category', $appx);
            if( $tmp !== false )
            {
                $app->app_filter_details['category'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->category = $tmp1->textContent;
                    $app->app_filter_details['category'][$tmp1->textContent] = $tmp1->textContent;

                }
            }

            $tmp = DH::findFirstElement('subcategory', $appx);
            if( $tmp !== false )
            {
                $app->app_filter_details['subcategory'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->subCategory = $tmp1->textContent;
                    $app->app_filter_details['subcategory'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('technology', $appx);
            if( $tmp !== false )
            {
                $app->app_filter_details['technology'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->technology = $tmp1->textContent;
                    $app->app_filter_details['technology'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('risk', $appx);
            if( $tmp !== false )
            {
                $app->app_filter_details['risk'] = array();
                foreach( $tmp->childNodes as $tmp1 )
                {
                    if( $tmp1->nodeType != XML_ELEMENT_NODE ) continue;
                    $app->risk = $tmp1->textContent;
                    $app->app_filter_details['risk'][$tmp1->textContent] = $tmp1->textContent;
                }
            }

            $tmp = DH::findFirstElement('evasive', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['evasive'] = true;
            }
            $tmp = DH::findFirstElement('excessive-bandwidth-use', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['excessive-bandwidth'] = true;
            }
            $tmp = DH::findFirstElement('used-by-malware', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['used-by-malware'] = true;
            }
            $tmp = DH::findFirstElement('transfers-files', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['transfers-files'] = true;
            }
            $tmp = DH::findFirstElement('has-known-vulnerabilities', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['vulnerabilities'] = true;
            }
            $tmp = DH::findFirstElement('tunnels-other-apps', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['tunnels-other-apps'] = true;
            }
            $tmp = DH::findFirstElement('prone-to-misuse', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['prone-to-misuse'] = true;
            }

            $tmp = DH::findFirstElement('pervasive', $appx);
            if( $tmp !== false )
            {
                if( $tmp->textContent == 'yes' )
                    $app->_characteristics['widely-used'] = true;
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


        $appid_version = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        self::$predefinedStore->predefinedStore_appid_version = $appid_version->nodeValue;

		// fixing someone mess ;)
		$app = $this->findOrCreate('ftp');
		$app->tcp[] = Array( 0 => 'dynamic');
	}

}





