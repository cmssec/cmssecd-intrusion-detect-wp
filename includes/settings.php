<?php

add_action( 'admin_post_update_settings', 'prefix_admin_update_settings' );

function prefix_admin_update_settings()
{
    status_header(200);
    die("Server received '{$_REQUEST}' from your browser.");
}

function make_settings()
{

    settings_fields('cmssecd_options_options' );
    do_settings_sections( 'cmssecd_options_options' );
    $checked = '';
    if (get_option('cmssecd_enabled')) {
        $checked = "checked";
    }
?>

	<div class="cmssec_settings_page">
        <div class="settings_form">
            <form action="options.php" method="post">
            <!--
            <input type="text" style="display: none;" name="action" value="update_settings" readonly>
            Plugin Enabled: <input type="checkbox" name="enabled"> <br />
            <input type="submit" value="Save">
            -->
            
                Plugin Enabled: <input type="checkbox" name="cmssecd_enabled" <?php $checked ?> > <br />
                Integrity Check Interval: <input type="text" name="cmssecd_interval" value="<?php echo esc_attr( get_option('cmssecd_interval') ); ?>">
                <?php submit_button(); ?>
            </form>
        </div>
    </div>
<?php

    #file_put_contents('/tmp/ret', print_r($h, true));
    #$html = PHP_EOL . file_get_contents(plugin_dir_path(__FILE__) . '/' . plugin_basename('../settings-page.php'));
    #return $h;
}
