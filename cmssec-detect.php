<?php
/*
Plugin Name: CMSSec Detect
Plugin URI: http://cmssec.co/cmssec-detect-plugin
Description: Intrusion detection plugin for wordpress by http://cmssec.co
Author: Jonathan Frakes, cmssec.co
Version: 1.0
Author URI: http://cmssec.co
*/
 
// Go ahead and edit stuff if you know what you're doing, if you're unsure or you need something that this plugin cannot do
// Feel free to contact me at contact me at tech@cmssec.co
 
//
#defined( 'ABSPATH' ) or die( 'Plugin file cannot be accessed directly.' );

require_once(ABSPATH . 'wp-admin/includes/file.php');

global $cmsecd_db_version;
$exts = array('php');
$cmssecd_db_version = '1.0';

if (!cmssecd_installed()) {
    cmssecd_install();
}

add_action('init', 'register_script');

function register_script() {
    //wp_register_script( 'custom_jquery', plugins_url('/js/custom-jquery.js', __FILE__), array('jquery'), '2.5.1' );
	wp_register_style('cmssecd_style', plugins_url('/assets/style.css', __FILE__), false, '1.0.0', 'all');
}

// use the registered jquery and style above
add_action('wp_enqueue_scripts', 'enqueue_style');

function enqueue_style(){
   //wp_enqueue_script('custom_jquery');
   wp_enqueue_style( 'cmssecd_style' );
}

cmssecd_init_filedb();
#cmssecd_geto();


function cmssecd_init_filedb()
{
    global $wpdb;
    global $exts;
    $dformat = "Y-m-d H:i:s";
    $now = date($dformat);
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(get_home_path()));
    
    $phpFiles = array(); 
    foreach ($rii as $file) {
        if (!$file->isDir()) {
            $p = pathinfo($file->getPathname());
            if (isset($p['extension'])) {
                if (in_array($p['extension'], $exts)) {
                    $fname  = $file->getPathName();
                    $md5    = md5_file($fname);
                    $sha256 = hash_file("sha256", $fname);
                    $adate  = date($dformat, fileatime($fname));
                    $mdate  = date($dformat, filemtime($fname));
                    $cdate  = date($dformat, filectime($fname));
                    $size   = filesize($fname);
                    $rights = substr(sprintf('%o', fileperms($fname)), -4);
                
                    $phpFiles[$fname] = array('md5' => $md5, 'sha256' => $sha256, 'adate' => $adate, 'mdate' => $mdate, 'cdate' => $cdate, 'size' => $size, 'rights' => $rights);
                }
            }
        }
    }
    
    return $phpFiles;    
    
}

// temporary function
function cmssecd_geto()
{
    global $wpdb;
    $q = "select * from $wpdb->options where option_name like 'cmssecd_%'";
    $results = $wpdb->get_results($q, ARRAY_A);
    
    file_put_contents("/tmp/res", print_r($results));
}

function cmssecd_worker() 
{
    $interval = get_option('cmssecd_interval');
    $last_run = get_option('cmssecd_lastrun');
    
    $date		= date_create();
    
    $int_diff	= date_timestamp_get(date($last_run, strtotime('+' . $interval . 'minutes')));
    $int_date	= date_timestamp_get($date);
    $lrun_date	= date_timestamp_get($last_run);
    $date_diff	= $int_date - $lrun_date;
    
    if ($int_diff > $date_diff) {
        $changed = compare_last_two();
        
        foreach ($changed as $key => $change) {
            if ($change == true) {
                update_option('cmssecd_changed_' . $key, $change);
            }
        }
    }
    
    // Update last run
    update_option('cmssecd_lastrun', date('Y-m-d H:i:s'));

}

function compare_last_two()
{
    global $wpdb;
    
    $results = $wpdb->get_results('SELECT DISTINCT(*) FROM ' . $wpdb->prefix . ' cmssecd ORDER by id DESC LIMIT 2' . '', ARRAY_A );

    /*
    $wpdb->query($wpdb->prepare( 
	"
		INSERT INTO $wpdb->postmeta
		( post_id, meta_key, meta_value )
		VALUES ( %d, %s, %s )
	", 
        10, 
	$metakey, 
	$metavalue));
    */
    
    $changed = array('md5sum' => false, 'sha256' => false, 'size' => false);
    
    if ($results[0]['md5sum'] != $results[1]['md5sum']) {
        $changed['md5sum'] == true;
    }
    
    if ($results[0]['sha256'] != $results[1]['sha256']) {
        $changed['sha256'] == true;
    }
    
    if ($results[0]['size'] != $results[1]['size']) {
        $changed['size'] == true;
    }
    
    return $changed;
    
}

function cmssecd_insertdb($params)
{
    if (count($params) != 10) {
        return false;
    }
    
    // TODO Add check for each param ?
    
    global $wpdb;
    $table_name = $wpdb->prefix . 'cmssecd';
    
    $filePath = $params['filePath'];
    $md5sum   = $params['md5sum'];
    $sha256   = $params['sha256'];
    $adate    = $params['adate'];
    $mdate    = $params['mdate'];
    $cdate    = $params['cdate'];
    $size     = $params['size'];
    $rights   = $params['rights'];
    $comments = $params['comments'];
    $createdd = $params['created_date'];
    
    //$sql = "INSERT INTO $table_name (filePath, md5sum, sha256, adate, mdate, cdate, size, rights, comments, created_date)
    //                                VALUES ($filePath, $md5sum, $sha256, $adate, $mdate, $cdate, $size, $rights, $comments, $createdd)";
                                    
    $wpdb->insert($table_name, array(
        'filePath' => $filePath,
        'md5sum' => $md5sum,
        'sha256' => $sha256,
        'adate' => $adate,
        'mdate' => $mdate,
        'cdate' => $cdate,
        'size' => $size,
        'rights' => $rights,
        'comments' => $comments,
        'created_date' => $createdd
    ));
                                    
}

function cmssecd_install()
{
	global $wpdb;
	global $cmssecd_db_version;

	$table_name = $wpdb->prefix . 'cmssec';
	
	$charset_collate = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE $table_name (
		id int(9) NOT NULL AUTO_INCREMENT,
		filePath text NOT NULL,
		md5sum varchar(32),
		sha256 varchar(64),
		adate datetime,
		mdate datetime,
		cdate datetime,
		size int,
		rights int,
		comments text,
		created_date datetime default '0000-00-00 00:00:00',
		PRIMARY KEY (`id`)
	) $charset_collate;";
	
	$sql_idx = "CREATE INDEX md5sum_i ON $table_name (md5sum) USING BTREE";
	require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
	
	dbDelta($sql);
	dbDelta($sql_idx);

	add_option('cmssecd_db_version', $cmssecd_db_version);
}

add_action('admin_menu', 'register_pages');
add_action('admin_init', 'cmssecd_options_init' );

function register_pages()
{
    add_menu_page('CMSSEC Page', 'CMSSEC Dashboard', 'manage_options', 'cmssec-page', 'main_page');
    add_submenu_page( 'cmssec-page', 'Scan for Malware', 'Malware Scan', 'manage_options', 'cmssec-scan', 'scan');
    add_submenu_page( 'cmssec-page', 'Firewall', 'Firewall', 'manage_options', 'cmssec-firewall', 'firewall');
    add_submenu_page( 'cmssec-page', 'WP Integrity', 'WP Integrity', 'manage_options', 'cmssec-wpintegrity', 'integrity');
    add_submenu_page( 'cmssec-page', 'Plugin Settings', 'Plugin Settings', 'manage_options', 'cmssec-settings', 'settings');
    add_submenu_page( 'cmssec-page', 'Contact CMSSEC', 'Contact CMSSEC', 'manage_options', 'cmssec-contact', 'contact');
}

function settings()
{
    echo init_menu();
    
    // lol. Is this require_once path for real ... ?
    require_once(plugin_dir_path(__FILE__) . '/' . plugin_basename( '/includes/settings.php'));
    echo make_settings();
    
    echo left_side();

}

function contact() 
{
    echo left_side();
}

function integrity()
{
    echo left_side();
}

function firewall()
{
    echo left_side();
}

function scan()
{

	echo left_side();
}

function main_page()
{

	echo left_side();
    
}

function init_menu()
{

    enqueue_style();
    $html = '
    <div class=\'cmssec_wrap\'>
    <div class=\'cmssec_headbox\'>
    </div>
    <div class="cmssec_main_wrap">
        <div class="cmssec_pl_wrap">
            <div class="cmssec_pl_menu">
                <a href="'.menu_page_url('cmssec-page', false).'">Dashboard</a>
                <a href="'.menu_page_url('cmssec-scan', false).'">Malware Scan</a>
                <a href="'.menu_page_url('cmssec-firewall', false).'">Firewall</a>
                <a href="'.menu_page_url('cmssec-wpintegrity', false).'">Wordpress Integrity</a>
                <a href="'.menu_page_url('cmssec-settings', false).'">Plugin Settings</a>
                <a href="'.menu_page_url('cmssec-contact', false).'">Message Us</a>
            </div>
        </div>
    </div>
    ';
    return $html;
}

function left_side()  
{

    enqueue_style();

    $html = PHP_EOL . file_get_contents(plugins_url('/html.html', __FILE__));
	return $html;
    
}

function status_show()
{
    echo "test";
}

function settings_show()
{
    echo "test";
}

// Init plugin options to white list our options
function cmssecd_options_init()
{
    register_setting( 'cmssecd_options_options', 'changed_md5sum' );
    register_setting( 'cmssecd_options_options', 'changed_sha256' );
    register_setting( 'cmssecd_options_options', 'changed_size' );
    register_setting( 'cmssecd_options_options', 'lastrun' );
    register_setting( 'cmssecd_options_options', 'interval' );
        
}

function cmssecd_installed()
{
    $go = get_option('cmssecd_db_version');
    if (!empty($go)) {
        return true;
    } else {
        return false;
    }
}

function cmssecd_enabled()
{
    $go = get_option('cmssecd_enabled');
    if (!empty($go) && $go == "enabled") {
        return true;
    } else {
        return false;
    }
}
